package internal

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SystemSnapshot struct {
	CPUPercent   float64
	MemoryPercent float64
	DiskPercent  float64
	DiskReadBps  float64
	DiskWriteBps float64
	NetworkInBps float64
	NetworkOutBps float64
	NetworkInterface string
}

type SystemMetricsCollector struct {
	Interface     string
	lastCPUTotal  uint64
	lastCPUIdle   uint64
	lastNetIn     uint64
	lastNetOut    uint64
	lastDiskRead  uint64
	lastDiskWrite uint64
	lastSampleAt  time.Time
}

func (c *SystemMetricsCollector) Snapshot() (SystemSnapshot, error) {
	now := time.Now()
	total, idle, err := readCPUStat()
	if err != nil {
		return SystemSnapshot{}, err
	}
	mem, err := readMemoryPercent()
	if err != nil {
		return SystemSnapshot{}, err
	}
	disk, err := readDiskPercent("/")
	if err != nil {
		return SystemSnapshot{}, err
	}
	netIn, netOut, ifaceUsed, err := readNetworkTotals(c.Interface)
	if err != nil {
		return SystemSnapshot{}, err
	}
	diskReadBytes, diskWriteBytes, err := readDiskIOTotals()
	if err != nil {
		return SystemSnapshot{}, err
	}

	snapshot := SystemSnapshot{
		CPUPercent:    0,
		MemoryPercent: mem,
		DiskPercent:   disk,
		DiskReadBps:   0,
		DiskWriteBps:  0,
		NetworkInBps:  0,
		NetworkOutBps: 0,
		NetworkInterface: ifaceUsed,
	}

	if !c.lastSampleAt.IsZero() {
		totalDelta := float64(total - c.lastCPUTotal)
		idleDelta := float64(idle - c.lastCPUIdle)
		if totalDelta > 0 {
			snapshot.CPUPercent = (1 - idleDelta/totalDelta) * 100
		}
		seconds := now.Sub(c.lastSampleAt).Seconds()
		if seconds > 0 {
			snapshot.NetworkInBps = float64(netIn-c.lastNetIn) / seconds
			snapshot.NetworkOutBps = float64(netOut-c.lastNetOut) / seconds
			snapshot.DiskReadBps = float64(diskReadBytes-c.lastDiskRead) / seconds
			snapshot.DiskWriteBps = float64(diskWriteBytes-c.lastDiskWrite) / seconds
		}
	}

	c.lastCPUTotal = total
	c.lastCPUIdle = idle
	c.lastNetIn = netIn
	c.lastNetOut = netOut
	c.lastDiskRead = diskReadBytes
	c.lastDiskWrite = diskWriteBytes
	c.lastSampleAt = now

	return snapshot, nil
}

func readCPUStat() (total uint64, idle uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	line := strings.Split(string(data), "\n")[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("invalid /proc/stat format")
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		v, convErr := strconv.ParseUint(field, 10, 64)
		if convErr != nil {
			return 0, 0, convErr
		}
		values = append(values, v)
		total += v
	}
	idle = values[3]
	return total, idle, nil
}

func readMemoryPercent() (float64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var total, available float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(line, "MemTotal: %f kB", &total)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(line, "MemAvailable: %f kB", &available)
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("failed to read memory stats")
	}
	return (1 - available/total) * 100, nil
}

func readDiskPercent(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	total := float64(stat.Blocks) * float64(stat.Bsize)
	free := float64(stat.Bavail) * float64(stat.Bsize)
	if total == 0 {
		return 0, nil
	}
	return (1 - free/total) * 100, nil
}

func readNetworkTotals(targetIface string) (uint64, uint64, string, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, "", err
	}
	var inTotal, outTotal uint64
	ifaceUsed := targetIface
	lines := strings.Split(string(data), "\n")
	matched := false
	for _, line := range lines[2:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		if targetIface != "" && iface != targetIface {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		inBytes, inErr := strconv.ParseUint(fields[0], 10, 64)
		outBytes, outErr := strconv.ParseUint(fields[8], 10, 64)
		if inErr != nil || outErr != nil {
			continue
		}
		matched = true
		if targetIface == "" {
			ifaceUsed = "all"
		}
		inTotal += inBytes
		outTotal += outBytes
	}
	if targetIface != "" && !matched {
		return 0, 0, targetIface, fmt.Errorf("network interface %s not found", targetIface)
	}
	return inTotal, outTotal, ifaceUsed, nil
}

func readDiskIOTotals() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0, err
	}
	var readTotal uint64
	var writeTotal uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		// major minor name reads ... sectors_read ... writes ... sectors_written ...
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		if !isWholeDiskDevice(name) {
			continue
		}
		readSectors, readErr := strconv.ParseUint(fields[5], 10, 64)
		writeSectors, writeErr := strconv.ParseUint(fields[9], 10, 64)
		if readErr != nil || writeErr != nil {
			continue
		}
		// Linux reports sectors in 512-byte units in /proc/diskstats.
		readTotal += readSectors * 512
		writeTotal += writeSectors * 512
	}
	return readTotal, writeTotal, nil
}

func isWholeDiskDevice(name string) bool {
	if strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd") {
		return len(name) == 3
	}
	if strings.HasPrefix(name, "nvme") {
		// Whole disks are like nvme0n1; partitions are nvme0n1p1.
		return strings.Contains(name, "n") && !strings.Contains(name, "p")
	}
	if strings.HasPrefix(name, "mmcblk") {
		return !strings.Contains(name, "p")
	}
	if strings.HasPrefix(name, "md") {
		return true
	}
	return false
}
