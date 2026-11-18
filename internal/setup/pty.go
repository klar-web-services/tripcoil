package setup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxCapture = 1 << 20

// runInPTY runs cmd on a new pseudo-terminal, passing in to it and what it prints to out. When
// in is a terminal, it takes its window size and is in raw mode meanwhile. It returns what cmd
// printed (the last MiB) and cmd's exit error.
func runInPTY(in *os.File, out io.Writer, cmd *exec.Cmd) ([]byte, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer master.Close()
	mfd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, fmt.Errorf("unlocking the pseudo-terminal: %v", err)
	}
	n, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		return nil, fmt.Errorf("numbering the pseudo-terminal: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer slave.Close()

	fd := int(in.Fd())
	done := make(chan struct{})
	if old, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
		resize := func() {
			if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil {
				unix.IoctlSetWinsize(mfd, unix.TIOCSWINSZ, ws)
			}
		}
		resize()
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for {
				select {
				case <-winch:
					resize()
				case <-done:
					return
				}
			}
		}()
		raw := *old
		raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
		raw.Oflag &^= unix.OPOST
		raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
		raw.Cflag &^= unix.CSIZE | unix.PARENB
		raw.Cflag |= unix.CS8
		raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
			close(done)
			return nil, err
		}
		defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	}

	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		close(done)
		return nil, err
	}
	slave.Close()

	// Polling with a timeout leaves no reader on in once cmd is done: the next question needs it.
	copiedIn := make(chan struct{})
	go func() {
		defer close(copiedIn)
		buf := make([]byte, 4096)
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := unix.Poll(fds, 100)
			if errors.Is(err, unix.EINTR) || n == 0 {
				continue
			}
			if err != nil {
				return
			}
			m, err := unix.Read(fd, buf)
			if m <= 0 || err != nil {
				return
			}
			if _, err := master.Write(buf[:m]); err != nil {
				return
			}
		}
	}()

	var capture []byte
	copiedOut := make(chan struct{})
	go func() {
		defer close(copiedOut)
		buf := make([]byte, 32*1024)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
				capture = append(capture, buf[:n]...)
				if len(capture) > maxCapture {
					capture = capture[len(capture)-maxCapture:]
				}
			}
			if err != nil { // EIO once cmd has exited and closed the pseudo-terminal
				return
			}
		}
	}()

	err = cmd.Wait()
	close(done)
	<-copiedIn
	// Something cmd started may still hold the pseudo-terminal; what cmd printed is there by now.
	master.SetReadDeadline(time.Now().Add(time.Second))
	<-copiedOut
	return capture, err
}
