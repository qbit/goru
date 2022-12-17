package main

import (
	"embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"

	expect "github.com/google/goexpect"
)

//go:embed autoinstall
var aiFS embed.FS

const diskLayout = `/	5G-*	95%
swap	1G
`

var mirror = "https://cdn.openbsd.org/pub/OpenBSD/%s/%s/%s"

var archMap = map[string]string{
	"arm64":   "arm64",
	"amd64":   "amd64",
	"i386":    "386",
	"octeon":  "mips64",
	"armv7":   "arm",
	"riscv64": "riscv64",
}

type nwc struct{}

func (n nwc) Write(p []byte) (int, error) {
	fmt.Print(string(p))
	return len(p), nil
}

func (n nwc) Close() error {
	return nil
}

type setList []string

func newSetList(sv string) setList {
	sl := setList{
		"SHA256.sig",
		"SHA256",

		"bsd",
		"bsd.mp",
		"bsd.rd",
		"index.txt",

		"base%s.tgz",
		"comp%s.tgz",
		"man%s.tgz",
		"xbase%s.tgz",
		"miniroot%s.img",
	}

	for s := range sl {
		if strings.Contains(sl[s], "%s") {
			sl[s] = fmt.Sprintf(sl[s], sv)
		}
	}

	return sl
}

type OpenBSD struct {
	arch     string   // arm64
	pkgArch  string   // aarch64
	qemuCmd  []string // qemu-system-aarch64 .....
	sets     setList
	instScpt string
}

func (o *OpenBSD) Verify(dest, ver, smushVer string) error {
	sig := "signify"
	if runtime.GOOS != "openbsd" {
		sig = "gosignify"
	}
	outDir := path.Join(dest, o.arch)
	for _, file := range o.sets {
		if file == "SHA256" || file == "SHA256.sig" || file == "index.txt" {
			continue
		}
		fmt.Printf("\tverifying %s\n", file)
		cmd := exec.Command(
			sig,
			"-C",
			"-p",
			fmt.Sprintf("/etc/signify/openbsd-%s-base.pub", smushVer),
			"-x",
			"SHA256.sig",
			file,
		)
		cmd.Dir = outDir
		if out, err := cmd.Output(); err != nil {
			return fmt.Errorf("verification of %q failed!\n%s\n%s", file, out, err)
		}

	}
	return nil
}

func (o *OpenBSD) Build(dest, ver, smushVer string) error {
	outDir := path.Join(dest, o.arch)

	fileServer := http.FileServer(http.Dir(outDir))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if r.URL.Path == "/disklabel" {
				fmt.Fprint(w, diskLayout)
				return
			}
			if r.URL.Path == "/install.conf" {
				fmt.Fprint(w, o.instScpt)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/pub") {
				r.URL.Path = strings.Replace(r.URL.Path, "/pub", "/", 1)
				fileServer.ServeHTTP(w, r)
				return
			}
			fmt.Fprintf(os.Stderr, "THERE %s", r.URL.Path)
		}

		if r.Method == "POST" {
			out, err := os.Create(path.Join(outDir, "sys.diff.b64"))
			if err != nil {
				http.Error(w, "Error reading request body",
					http.StatusInternalServerError)
				return
			}
			defer out.Close()

			_, err = io.Copy(out, r.Body)
			if err != nil {
				http.Error(w, "Error writing request body",
					http.StatusInternalServerError)
				return
			}
		}
	})

	// This serves the various files over http for use with autoinstall
	ser := &http.Server{
		// BSD in asci / 26 (the current # of years openbsd has been around)
		Addr:    ":25706",
		Handler: mux,
	}

	go ser.ListenAndServe()
	defer ser.Close()

	imgcmd := exec.Command(
		"qemu-img",
		"create",
		"-f",
		"raw",
		"-o", "preallocation=full",
		"disk.raw",
		"10240M",
	)
	imgcmd.Dir = outDir
	if out, err := imgcmd.Output(); err != nil {
		return fmt.Errorf("image creation faild for %q: %s", out, err)
	}
	ddcmd := exec.Command(
		"dd",
		"conv=notrunc",
		fmt.Sprintf("if=miniroot%s.img", smushVer),
		"of=disk.raw",
	)
	ddcmd.Dir = outDir
	ddcmd.Run()

	qemucmd, _, err := expect.SpawnWithArgs(
		o.qemuCmd,
		1*time.Hour,
		expect.Tee(nwc{}),
	)
	if err != nil {
		return err
	}
	defer qemucmd.Close()

	_, _ = qemucmd.ExpectBatch([]expect.Batcher{
		&expect.BExp{R: "boot>$"},
		&expect.BSnd{S: "set tty com0\n"},
		&expect.BExp{R: "boot>"},
		&expect.BSnd{S: "\n"},
		&expect.BExp{R: "utoinstall or"},
		&expect.BSnd{S: "a\n"},
		&expect.BExp{R: "Response file"},
		&expect.BSnd{S: "http://10.0.2.2:25706/install.conf\n"},
		&expect.BExp{R: "login:"},
		&expect.BSnd{S: "root\n"},
		&expect.BExp{R: "Password:"},
		&expect.BSnd{S: "root\n"},
		&expect.BExp{R: "buildlet#"},
		&expect.BSnd{S: "env PKG_PATH=http://cdn.openbsd.org/%m pkg_add bash git go\n"},
		&expect.BExp{R: "buildlet#"},
		&expect.BSnd{S: "su - gopher\n"},
		&expect.BExp{R: "buildlet\\$"},
		&expect.BSnd{S: "git clone https://github.com/golang/sys\n"},
		&expect.BExp{R: "buildlet\\$"},
		&expect.BSnd{S: "cd sys/unix\n"},
		&expect.BExp{R: "buildlet\\$"},
		&expect.BSnd{S: fmt.Sprintf("env GOOS=openbsd GOARCH=%s ./mkall.sh\n", archMap[o.arch])},
		&expect.BExp{R: "buildlet\\$"},
		&expect.BSnd{S: fmt.Sprintf("env GOOS=openbsd GOARCH=%s go test ./...\n", archMap[o.arch])},
		&expect.BExp{R: "buildlet\\$"},
		&expect.BSnd{S: "git diff | openssl enc -base64 >/tmp/sys.diff.b64\n"},
		&expect.BExp{R: "buildlet\\$"},
		&expect.BSnd{S: "curl -d @/tmp/sys.diff.b64 http://10.0.2.2:25706/\n"},
		&expect.BExp{R: "buildlet\\$"},
		&expect.BSnd{S: "\n"},
	}, 30*time.Minute)

	return nil
}

func (o *OpenBSD) Fetch(dest, ver string) error {
	outDir := path.Join(dest, o.arch)
	err := os.MkdirAll(outDir, 0750)
	if err != nil && !os.IsExist(err) {
		return err
	}

	for _, file := range o.sets {
		fp := path.Join(outDir, file)
		fmt.Printf("\tfetching %q\n", file)
		// Always fetch SHA256.sig and missing files
		if _, err := os.Stat(fp); file == "SHA256.sig" || os.IsNotExist(err) {
			resp, err := http.Get(fmt.Sprintf(mirror, ver, o.arch, file))
			if err != nil {
				return err
			}

			defer resp.Body.Close()

			if resp.StatusCode == 404 {
				// allow failure of "bsd.mp"
				if file != "bsd.mp" {
					return fmt.Errorf("can't find %q for %q", file, o.arch)
				} else {
					fmt.Printf("\tskipping %q for %q\n", file, o.arch)
				}
				continue
			}

			out, err := os.Create(fp)
			if err != nil {
				return err
			}
			defer out.Close()

			_, err = io.Copy(out, resp.Body)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type Sets []OpenBSD

func (s Sets) Sort() {
	sort.Slice(s, func(i, j int) bool {
		return s[i].arch < s[j].arch
	})
}

func usage() {
	fmt.Println("usage: go run build.go [openbsd_release]")
	os.Exit(1)
}

func readAI(name string) string {
	s, err := aiFS.ReadFile(path.Join("autoinstall", name))
	if err != nil {
		log.Fatal(err)
	}
	return string(s)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}
	release := os.Args[1]
	smushVer := strings.ReplaceAll(release, ".", "")

	dest := path.Join("/tmp/openbsd", release)
	err := os.MkdirAll(dest, 0750)
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}

	sets := Sets{
		//{
		//	arch:     "arm64",
		//	pkgArch:  "aarch64",
		//	sets:     newSetList(smushVer),
		//	instScpt: readAI("arm64-autoinstall.conf"),
		//	qemuCmd: []string{
		//		"qemu-system-aarch64",
		//		"-M", "virt",
		//		"-nographic",
		//		"-cpu", "cortex-a57",
		//		"-m", "2048",
		//		"-smp", "4",
		//		"-net", "nic,model=e1000",
		//		"-net", "user",
		//		"-drive",
		//		fmt.Sprintf("file=%s,format=raw", path.Join(dest, "arm64", "disk.raw")),
		//	},
		//},
		{
			arch:     "amd64",
			pkgArch:  "amd64",
			sets:     newSetList(smushVer),
			instScpt: readAI("amd64-autoinstall.conf"),
			qemuCmd: []string{
				"qemu-system-x86_64",
				"-nographic",
				"-m", "2048",
				"-smp", "4",
				"-net", "nic,model=e1000",
				"-net", "user",
				"-drive",
				fmt.Sprintf("file=%s,format=raw", path.Join(dest, "amd64", "disk.raw")),
			},
		},
		{
			arch:     "i386",
			pkgArch:  "i386",
			sets:     newSetList(smushVer),
			instScpt: readAI("i386-autoinstall.conf"),
			qemuCmd: []string{
				"qemu-system-i386",
				"-nographic",
				"-m", "2048",
				"-smp", "4",
				"-net", "nic,model=e1000",
				"-net", "user",
				"-drive",
				fmt.Sprintf("file=%s,format=raw", path.Join(dest, "i386", "disk.raw")),
			},
		},
		//{
		//	arch:     "octeon",
		//	pkgArch:  "mips64",
		//	sets:     newSetList(smushVer),
		//	instScpt: readAI("octeon-autoinstall.conf"),
		//	qemuCmd: []string{
		//		"qemu-system-mips64",
		//		"-nographic",
		//		"-m", "2048",
		//		"-smp", "4",
		//		"-net", "nic,model=e1000",
		//		"-net", "user",
		//		"-drive",
		//		fmt.Sprintf("file=%s,format=raw", path.Join(dest, "octeon", "disk.raw")),
		//	},
		//},
		//{
		//	arch:     "armv7",
		//	pkgArch:  "arm",
		//	sets:     newSetList(smushVer),
		//	instScpt: readAI("armv7-autoinstall.conf"),
		//	qemuCmd: []string{
		//		"qemu-system-arm",
		//		"-nographic",
		//		"-m", "2048",
		//		"-net", "nic,model=e1000",
		//		"-net", "user",
		//		"-drive",
		//		fmt.Sprintf("file=%s,format=raw", path.Join(dest, "armv7", "disk.raw")),
		//	},
		//},
		//{
		//	arch:     "riscv64",
		//	pkgArch:  "riscv64",
		//	sets:     newSetList(smushVer),
		//	instScpt: readAI("riscv64-autoinstall.conf"),
		//	qemuCmd: []string{
		//		"qemu-system-riscv64",
		//		"-nographic",
		//		"-m", "2048",
		//		"-net", "nic,model=e1000",
		//		"-net", "user",
		//		"-drive",
		//		fmt.Sprintf("file=%s,format=raw", path.Join(dest, "riscv64", "disk.raw")),
		//	},
		//},
	}

	sets.Sort()

	for _, set := range sets {
		log.Printf("Fetching sets for %s\n", set.arch)
		err = set.Fetch(dest, release)
		if err != nil {
			log.Fatal(err)
		}
		err = set.Verify(dest, release, smushVer)
		if err != nil {
			log.Fatal(err)
		}

		err = set.Build(dest, release, smushVer)
		if err != nil {
			log.Fatal(err)
		}
	}
}
