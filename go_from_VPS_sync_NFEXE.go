// To build a windowless executable on Windows, use the following command:
// go build -ldflags="-H windowsgui" -o "vps_sync-2025-8-1-1.exe"

package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func hideConsoleWindow() {
	console := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow")
	if console.Find() != nil {
		return
	}
	hide := syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")
	if hide.Find() != nil {
		return
	}
	hwnd, _, _ := console.Call()
	if hwnd == 0 {
		return
	}
	hide.Call(hwnd, 0)
}

func checkSingleInstance() bool {
	mutexName := "Global\\VPSSync_SingleInstance_Mutex_12345"
	
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")
	
	mutexNamePtr, err := syscall.UTF16PtrFromString(mutexName)
	if err != nil {
		showMessageBox("错误", "无法创建互斥体名称")
		return false
	}
	
	handle, _, err := createMutex.Call(
		0,  // 默认安全属性
		1,  // 初始拥有者
		uintptr(unsafe.Pointer(mutexNamePtr)),
	)
	
	if handle == 0 {
		showMessageBox("错误", "无法创建互斥体")
		return false
	}
	
	// 检查GetLastError，如果返回ERROR_ALREADY_EXISTS (183)则说明已有实例
	if err.(syscall.Errno) == 183 {
		return false
	}
	
	return true
}

func showMessageBox(title, message string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")
	
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)
	
	messageBox.Call(
		0,  // 父窗口句柄
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		0x40, // MB_ICONINFORMATION
	)
}

type Config struct {
	VPSHost                string   `json:"vps_host"`
	VPSPort               int      `json:"vps_port"`
	VPSUsername           string   `json:"vps_username"`
	VPSPassword           string   `json:"vps_password"`
	VPSKeyFile            string   `json:"vps_key_file,omitempty"`
	RemoteWatchPath       string   `json:"remote_watch_path"`
	LocalSyncPath         string   `json:"local_sync_path"`
	SyncInterval          int      `json:"sync_interval"`
	MaxRetries            int      `json:"max_retries"`
	ExcludePatterns       []string `json:"exclude_patterns"`
	Recursive             bool     `json:"recursive"`
	CheckInterval         int      `json:"check_interval"`
	MaxConcurrentDownloads int     `json:"max_concurrent_downloads"`
	ChunkSize             int      `json:"chunk_size"`
	EnableResume          bool     `json:"enable_resume"`
	LargeFileThreshold    int64    `json:"large_file_threshold"`
	BufferSize            int      `json:"buffer_size"`
	MirrorSync            bool     `json:"mirror_sync"`
	DeleteLocalFiles      bool     `json:"delete_local_files"`
	UseChecksumVerify     bool     `json:"use_checksum_verify"`
}

type FileInfo struct {
	Path    string
	Size    int64
	ModTime int64
}

type SyncTask struct {
	RemotePath string
	LocalPath  string
	Size       int64
}

type DeleteTask struct {
	LocalPath string
	IsDir     bool
}

type VPSSync struct {
	config       *Config
	sshClient    *ssh.Client
	sftpClient   *sftp.Client
	fileCache    map[string]FileInfo
	syncQueue    chan SyncTask
	deleteQueue  chan DeleteTask
	remoteFiles  map[string]bool
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewVPSSync(configPath string) (*VPSSync, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	return &VPSSync{
		config:      config,
		fileCache:   make(map[string]FileInfo),
		syncQueue:   make(chan SyncTask, 1000),
		deleteQueue: make(chan DeleteTask, 1000),
		remoteFiles: make(map[string]bool),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

func loadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// 设置默认值
	if config.VPSPort == 0 {
		config.VPSPort = 22
	}
	if config.MaxConcurrentDownloads == 0 {
		config.MaxConcurrentDownloads = 16
	}
	if config.ChunkSize == 0 {
		config.ChunkSize = 1024 * 1024 // 1MB
	}
	if config.LargeFileThreshold == 0 {
		config.LargeFileThreshold = 10 * 1024 * 1024 // 10MB
	}
	if config.BufferSize == 0 {
		config.BufferSize = 64 * 1024 // 64KB
	}

	return &config, nil
}

func (vs *VPSSync) Connect() error {
	sshConfig := &ssh.ClientConfig{
		User:            vs.config.VPSUsername,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	// 认证方式
	if vs.config.VPSPassword != "" {
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.Password(vs.config.VPSPassword),
		}
	} else if vs.config.VPSKeyFile != "" {
		key, err := os.ReadFile(vs.config.VPSKeyFile)
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return err
		}
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	}

	addr := fmt.Sprintf("%s:%d", vs.config.VPSHost, vs.config.VPSPort)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return err
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return err
	}

	vs.sshClient = client
	vs.sftpClient = sftpClient
	
	log.Printf("成功连接到VPS: %s", vs.config.VPSHost)
	return nil
}

func (vs *VPSSync) Disconnect() {
	if vs.sftpClient != nil {
		vs.sftpClient.Close()
	}
	if vs.sshClient != nil {
		vs.sshClient.Close()
	}
}

func (vs *VPSSync) shouldExclude(path string) bool {
	for _, pattern := range vs.config.ExcludePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func (vs *VPSSync) scanLocalFiles(localPath string, remoteBasePath string) error {
	return filepath.Walk(localPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过根目录
		if path == localPath {
			return nil
		}

		// 计算相对路径
		relPath, err := filepath.Rel(localPath, path)
		if err != nil {
			return err
		}

		// 转换为远程路径格式（使用正斜杠）
		remotePath := remoteBasePath + "/" + strings.ReplaceAll(relPath, "\\", "/")
		remotePath = strings.ReplaceAll(remotePath, "//", "/")

		// 检查是否应该排除
		if vs.shouldExclude(remotePath) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		vs.mu.RLock()
		exists := vs.remoteFiles[remotePath]
		vs.mu.RUnlock()

		// 如果远程不存在此文件/目录，加入删除队列
		if !exists && vs.config.MirrorSync && vs.config.DeleteLocalFiles {
			select {
			case vs.deleteQueue <- DeleteTask{
				LocalPath: path,
				IsDir:     info.IsDir(),
			}:
				log.Printf("本地多余文件/目录已加入删除队列: %s", path)
			case <-vs.ctx.Done():
				return vs.ctx.Err()
			}
		}

		return nil
	})
}

func (vs *VPSSync) scanDirectory(remotePath, localBase string) error {
	log.Printf("扫描目录: %s", remotePath)
	
	entries, err := vs.sftpClient.ReadDir(remotePath)
	if err != nil {
		log.Printf("读取目录失败 %s: %v", remotePath, err)
		return err
	}

	log.Printf("发现 %d 个条目在目录: %s", len(entries), remotePath)

	for _, entry := range entries {
		// 修复路径拼接问题 - 使用正斜杠而不是filepath.Join
		remoteItemPath := remotePath + "/" + entry.Name()
		// 清理双斜杠
		remoteItemPath = strings.ReplaceAll(remoteItemPath, "//", "/")
		
		log.Printf("处理条目: %s (大小: %d, 是否目录: %v)", remoteItemPath, entry.Size(), entry.IsDir())
		
		if vs.shouldExclude(remoteItemPath) {
			log.Printf("排除文件: %s", remoteItemPath)
			continue
		}

		// 记录远程文件/目录
		vs.mu.Lock()
		vs.remoteFiles[remoteItemPath] = true
		vs.mu.Unlock()

		// 计算相对路径
		relPath := strings.TrimPrefix(remoteItemPath, vs.config.RemoteWatchPath)
		relPath = strings.TrimPrefix(relPath, "/")
		
		// 转换为本地路径格式
		localPath := filepath.Join(localBase, relPath)
		
		log.Printf("映射路径: %s -> %s", remoteItemPath, localPath)

		if entry.IsDir() {
			if vs.config.Recursive {
				log.Printf("创建本地目录: %s", localPath)
				if err := os.MkdirAll(localPath, 0755); err != nil {
					log.Printf("创建目录失败 %s: %v", localPath, err)
				}
				// 递归扫描子目录
				if err := vs.scanDirectory(remoteItemPath, localBase); err != nil {
					log.Printf("递归扫描失败 %s: %v", remoteItemPath, err)
				}
			}
		} else {
			fileInfo := FileInfo{
				Path:    remoteItemPath,
				Size:    entry.Size(),
				ModTime: entry.ModTime().Unix(),
			}

			needsSync := false
			reason := ""

			// 首先检查本地文件是否存在
			localStat, localErr := os.Stat(localPath)
			if localErr != nil {
				needsSync = true
				reason = "本地文件不存在"
			} else {
				// 详细记录时间和大小信息用于调试
				localTime := localStat.ModTime().Unix()
				remoteTime := fileInfo.ModTime
				timeDiff := abs(localTime - remoteTime)
				
				log.Printf("调试信息 - 文件: %s", remoteItemPath)
				log.Printf("  本地大小: %d, 远程大小: %d", localStat.Size(), fileInfo.Size)
				log.Printf("  本地时间: %d (%s)", localTime, time.Unix(localTime, 0).Format("2006-01-02 15:04:05"))
				log.Printf("  远程时间: %d (%s)", remoteTime, time.Unix(remoteTime, 0).Format("2006-01-02 15:04:05"))
				log.Printf("  时间差异: %d 秒", timeDiff)
				
				// 本地文件存在，进行各项比较
				if localStat.Size() != fileInfo.Size {
					needsSync = true
					reason = fmt.Sprintf("文件大小不同 (本地:%d vs 远程:%d)", localStat.Size(), fileInfo.Size)
				} else if timeDiff > 2 {
					// 允许2秒的时间误差（考虑到网络延迟和精度问题）
					needsSync = true
					reason = fmt.Sprintf("修改时间不同 (本地:%s vs 远程:%s, 相差%d秒)", 
						time.Unix(localTime, 0).Format("2006-01-02 15:04:05"),
						time.Unix(remoteTime, 0).Format("2006-01-02 15:04:05"),
						timeDiff)
				} else if vs.config.UseChecksumVerify {
					// 如果大小和时间都相同，但启用了校验和验证
					log.Printf("  开始校验和检查...")
					localChecksum, err1 := calculateFileChecksum(localPath)
					if err1 == nil {
						remoteChecksum, err2 := vs.calculateRemoteFileChecksum(remoteItemPath)
						if err2 == nil {
							log.Printf("  本地校验和: %s", localChecksum)
							log.Printf("  远程校验和: %s", remoteChecksum)
							if localChecksum != remoteChecksum {
								needsSync = true
								reason = fmt.Sprintf("校验和不匹配 (本地:%s vs 远程:%s)", localChecksum[:8], remoteChecksum[:8])
							}
						} else {
							log.Printf("  获取远程校验和失败: %v", err2)
						}
					} else {
						log.Printf("  获取本地校验和失败: %v", err1)
					}
				}
			}

			// 更新缓存
			vs.mu.Lock()
			vs.fileCache[remoteItemPath] = fileInfo
			vs.mu.Unlock()

			if needsSync {
				log.Printf("文件需要同步: %s (大小: %d) - 原因: %s", remoteItemPath, entry.Size(), reason)
				
				vs.mu.Lock()
				vs.fileCache[remoteItemPath] = fileInfo
				vs.mu.Unlock()

				select {
				case vs.syncQueue <- SyncTask{
					RemotePath: remoteItemPath,
					LocalPath:  localPath,
					Size:       entry.Size(),
				}:
					log.Printf("文件已加入同步队列: %s", remoteItemPath)
				case <-vs.ctx.Done():
					return vs.ctx.Err()
				}
			} else {
				log.Printf("文件无需同步: %s", remoteItemPath)
			}
		}
	}

	return nil
}

func (vs *VPSSync) deleteLocalFile(task DeleteTask) error {
	log.Printf("删除本地文件/目录: %s (是否目录: %v)", task.LocalPath, task.IsDir)
	
	if task.IsDir {
		err := os.RemoveAll(task.LocalPath)
		if err != nil {
			return fmt.Errorf("删除本地目录失败: %v", err)
		}
		log.Printf("成功删除本地目录: %s", task.LocalPath)
	} else {
		err := os.Remove(task.LocalPath)
		if err != nil {
			return fmt.Errorf("删除本地文件失败: %v", err)
		}
		log.Printf("成功删除本地文件: %s", task.LocalPath)
	}
	
	return nil
}

func (vs *VPSSync) downloadFile(task SyncTask) error {
	log.Printf("开始下载文件: %s -> %s", task.RemotePath, task.LocalPath)
	
	// 确保本地目录存在
	if err := os.MkdirAll(filepath.Dir(task.LocalPath), 0755); err != nil {
		return fmt.Errorf("创建本地目录失败: %v", err)
	}

	// 检查是否需要断点续传
	var resumePos int64 = 0
	var forceRedownload bool = false
	
	if vs.config.EnableResume {
		if stat, err := os.Stat(task.LocalPath); err == nil {
			if stat.Size() == task.Size {
				// 获取远程文件时间信息进行进一步检查
				remoteInfo, remoteErr := vs.sftpClient.Stat(task.RemotePath)
				if remoteErr == nil {
					localTime := stat.ModTime().Unix()
					remoteTime := remoteInfo.ModTime().Unix()
					timeDiff := abs(localTime - remoteTime)
					
					log.Printf("文件大小相同，检查时间差异: %d秒", timeDiff)
					
					// 如果时间差异超过2秒，强制重新下载
					if timeDiff > 2 {
						log.Printf("时间差异太大，强制重新下载: %s", task.RemotePath)
						forceRedownload = true
					} else {
						log.Printf("文件已存在且完整，跳过: %s", task.RemotePath)
						return nil
					}
				} else {
					log.Printf("无法获取远程文件信息，跳过: %s", task.RemotePath)
					return nil
				}
			} else if stat.Size() < task.Size {
				resumePos = stat.Size()
				log.Printf("断点续传，从位置 %d 开始: %s", resumePos, task.RemotePath)
			} else {
				log.Printf("本地文件更大，删除重新下载: %s", task.LocalPath)
				forceRedownload = true
			}
		}
	}
	
	// 如果需要强制重新下载，删除本地文件
	if forceRedownload {
		os.Remove(task.LocalPath)
		resumePos = 0
	}

	// 大文件使用分块下载
	if task.Size > vs.config.LargeFileThreshold {
		return vs.downloadFileChunked(task, resumePos)
	}

	return vs.downloadFileSimple(task, resumePos)
}

func (vs *VPSSync) downloadFileSimple(task SyncTask, resumePos int64) error {
	remoteFile, err := vs.sftpClient.Open(task.RemotePath)
	if err != nil {
		return fmt.Errorf("打开远程文件失败: %v", err)
	}
	defer remoteFile.Close()

	var localFile *os.File
	if resumePos > 0 {
		localFile, err = os.OpenFile(task.LocalPath, os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("打开本地文件失败: %v", err)
		}
		remoteFile.Seek(resumePos, 0)
	} else {
		localFile, err = os.Create(task.LocalPath)
		if err != nil {
			return fmt.Errorf("创建本地文件失败: %v", err)
		}
	}
	defer localFile.Close()

	buffer := make([]byte, vs.config.BufferSize)
	copied, err := io.CopyBuffer(localFile, remoteFile, buffer)
	if err != nil {
		return fmt.Errorf("复制文件内容失败: %v", err)
	}

	// 设置本地文件的修改时间为远程文件的修改时间
	if remoteInfo, err := vs.sftpClient.Stat(task.RemotePath); err == nil {
		remoteTime := remoteInfo.ModTime()
		log.Printf("设置文件时间 %s: %s", task.LocalPath, remoteTime.Format("2006-01-02 15:04:05"))
		if err := os.Chtimes(task.LocalPath, remoteTime, remoteTime); err != nil {
			log.Printf("设置文件时间失败: %v", err)
		} else {
			log.Printf("文件时间设置成功")
		}
	} else {
		log.Printf("获取远程文件时间失败: %v", err)
	}

	log.Printf("下载文件成功: %s -> %s (复制了 %d 字节)", task.RemotePath, task.LocalPath, copied)
	return nil
}

func (vs *VPSSync) downloadFileChunked(task SyncTask, resumePos int64) error {
	chunkSize := int64(vs.config.ChunkSize)
	numChunks := (task.Size - resumePos + chunkSize - 1) / chunkSize
	
	log.Printf("开始分块下载: %s (大小: %dMB, 分块数: %d)", 
		task.RemotePath, task.Size/1024/1024, numChunks)

	tempPath := task.LocalPath + ".tmp"
	
	// 如果是断点续传，复制已下载部分
	if resumePos > 0 {
		if err := copyFile(task.LocalPath, tempPath); err != nil {
			return err
		}
	}

	tempFile, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer tempFile.Close()

	if resumePos > 0 {
		tempFile.Seek(resumePos, 0)
	}

	// 并发下载分块
	chunkChan := make(chan ChunkResult, int(numChunks))
	var wg sync.WaitGroup

	maxWorkers := min(int64(4), numChunks)
	semaphore := make(chan struct{}, maxWorkers)

	for i := int64(0); i < numChunks; i++ {
		wg.Add(1)
		go func(chunkIndex int64) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			startPos := resumePos + chunkIndex*chunkSize
			endPos := min(startPos+chunkSize-1, task.Size-1)

			data, err := vs.downloadChunk(task.RemotePath, startPos, endPos)
			chunkChan <- ChunkResult{
				Index: chunkIndex,
				Data:  data,
				Error: err,
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(chunkChan)
	}()

	// 按顺序写入分块
	chunks := make(map[int64][]byte)
	for result := range chunkChan {
		if result.Error != nil {
			return result.Error
		}
		chunks[result.Index] = result.Data
	}

	for i := int64(0); i < numChunks; i++ {
		if data, ok := chunks[i]; ok {
			if _, err := tempFile.Write(data); err != nil {
				return err
			}
		}
	}

	tempFile.Close()

	// 重命名临时文件
	if err := os.Rename(tempPath, task.LocalPath); err != nil {
		return err
	}

	// 设置本地文件的修改时间为远程文件的修改时间
	if remoteInfo, err := vs.sftpClient.Stat(task.RemotePath); err == nil {
		remoteTime := remoteInfo.ModTime()
		log.Printf("设置文件时间 %s: %s", task.LocalPath, remoteTime.Format("2006-01-02 15:04:05"))
		if err := os.Chtimes(task.LocalPath, remoteTime, remoteTime); err != nil {
			log.Printf("设置文件时间失败: %v", err)
		} else {
			log.Printf("文件时间设置成功")
		}
	} else {
		log.Printf("获取远程文件时间失败: %v", err)
	}

	log.Printf("分块下载完成: %s", task.RemotePath)
	return nil
}

type ChunkResult struct {
	Index int64
	Data  []byte
	Error error
}

func (vs *VPSSync) downloadChunk(remotePath string, startPos, endPos int64) ([]byte, error) {
	// 为分块下载创建新的连接
	sshConfig := &ssh.ClientConfig{
		User:            vs.config.VPSUsername,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	// 认证方式
	if vs.config.VPSPassword != "" {
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.Password(vs.config.VPSPassword),
		}
	} else if vs.config.VPSKeyFile != "" {
		key, err := os.ReadFile(vs.config.VPSKeyFile)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", vs.config.VPSHost, vs.config.VPSPort), sshConfig)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}
	defer sftpClient.Close()

	file, err := sftpClient.Open(remotePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	file.Seek(startPos, 0)
	data := make([]byte, endPos-startPos+1)
	_, err = io.ReadFull(file, data)
	return data, err
}

func (vs *VPSSync) monitorLoop() {
	ticker := time.NewTicker(time.Duration(vs.config.CheckInterval) * time.Second)
	defer ticker.Stop()

	log.Printf("开始监控远程目录: %s", vs.config.RemoteWatchPath)

	for {
		select {
		case <-vs.ctx.Done():
			return
		case <-ticker.C:
			log.Printf("开始扫描远程目录...")
			
			// 清空远程文件列表
			vs.mu.Lock()
			vs.remoteFiles = make(map[string]bool)
			vs.mu.Unlock()
			
			// 扫描远程目录
			err := vs.scanDirectory(vs.config.RemoteWatchPath, vs.config.LocalSyncPath)
			if err != nil {
				log.Printf("扫描目录失败: %v", err)
				// 尝试重新连接
				vs.Disconnect()
				if err := vs.Connect(); err != nil {
					log.Printf("重新连接失败: %v", err)
				}
			} else {
				// 如果启用镜像同步，扫描本地文件以查找需要删除的文件
				if vs.config.MirrorSync {
					log.Printf("开始扫描本地文件，查找需要删除的文件...")
					if err := vs.scanLocalFiles(vs.config.LocalSyncPath, vs.config.RemoteWatchPath); err != nil {
						log.Printf("扫描本地文件失败: %v", err)
					}
				}
			}
			
			log.Printf("目录扫描完成")
		}
	}
}

func (vs *VPSSync) syncLoop() {
	ticker := time.NewTicker(time.Duration(vs.config.SyncInterval) * time.Second)
	defer ticker.Stop()

	var syncTasks []SyncTask
	var deleteTasks []DeleteTask
	
	for {
		select {
		case <-vs.ctx.Done():
			return
		case task := <-vs.syncQueue:
			syncTasks = append(syncTasks, task)
			log.Printf("收到同步任务: %s (队列长度: %d)", task.RemotePath, len(syncTasks))
		case task := <-vs.deleteQueue:
			deleteTasks = append(deleteTasks, task)
			log.Printf("收到删除任务: %s (队列长度: %d)", task.LocalPath, len(deleteTasks))
		case <-ticker.C:
			totalTasks := len(syncTasks) + len(deleteTasks)
			if totalTasks == 0 {
				continue
			}

			log.Printf("开始处理 %d 个同步任务和 %d 个删除任务", len(syncTasks), len(deleteTasks))
			
			// 处理删除任务
			if len(deleteTasks) > 0 {
				log.Printf("开始处理删除任务...")
				for _, task := range deleteTasks {
					if err := vs.deleteLocalFile(task); err != nil {
						log.Printf("删除失败: %s - %v", task.LocalPath, err)
					}
				}
				deleteTasks = deleteTasks[:0] // 清空切片
			}
			
			// 处理同步任务
			if len(syncTasks) > 0 {
				log.Printf("开始处理同步任务...")
				// 使用goroutine池并发下载
				semaphore := make(chan struct{}, vs.config.MaxConcurrentDownloads)
				var wg sync.WaitGroup
				
				for _, task := range syncTasks {
					wg.Add(1)
					go func(t SyncTask) {
						defer wg.Done()
						semaphore <- struct{}{}
						defer func() { <-semaphore }()
						
						for retry := 0; retry < vs.config.MaxRetries; retry++ {
							if err := vs.downloadFile(t); err != nil {
								log.Printf("下载失败 (重试 %d/%d): %s - %v", 
									retry+1, vs.config.MaxRetries, t.RemotePath, err)
								time.Sleep(time.Duration(1<<retry) * time.Second)
							} else {
								break
							}
						}
					}(task)
				}
				
				wg.Wait()
				syncTasks = syncTasks[:0] // 清空切片
			}
			
			log.Printf("批次处理完成，处理了 %d 个任务", totalTasks)
		}
	}
}

func (vs *VPSSync) Start() error {
	if err := vs.Connect(); err != nil {
		return err
	}

	// 创建本地同步目录
	if err := os.MkdirAll(vs.config.LocalSyncPath, 0755); err != nil {
		return err
	}

	// 启动监控和同步goroutine
	go vs.monitorLoop()
	go vs.syncLoop()

	if vs.config.MirrorSync {
		log.Println("VPS目录镜像同步服务已启动")
	} else {
		log.Println("VPS目录单向同步服务已启动")
	}
	return nil
}

func (vs *VPSSync) Stop() {
	log.Println("停止VPS目录同步服务...")
	vs.cancel()
	vs.Disconnect()
	log.Println("VPS目录同步服务已停止")
}

// 辅助函数
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// calculateFileChecksum 计算文件的MD5校验和
func calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// calculateRemoteFileChecksum 计算远程文件的MD5校验和
func (vs *VPSSync) calculateRemoteFileChecksum(remotePath string) (string, error) {
	file, err := vs.sftpClient.Open(remotePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func createSampleConfig() {
	config := Config{
		VPSHost:                "your_vps_ip",
		VPSPort:               22,
		VPSUsername:           "your_username",
		VPSPassword:           "your_password",
		VPSKeyFile:            "",
		RemoteWatchPath:       "/path/to/remote/directory",
		LocalSyncPath:         "C:\\sync\\local_directory",
		SyncInterval:          5,
		MaxRetries:            3,
		ExcludePatterns:       []string{".tmp", ".log", "__pycache__", ".git"},
		Recursive:             true,
		CheckInterval:         30,
		MaxConcurrentDownloads: 16,
		ChunkSize:             1024 * 1024,
		EnableResume:          true,
		LargeFileThreshold:    10 * 1024 * 1024,
		BufferSize:            64 * 1024,
		MirrorSync:            false,
		DeleteLocalFiles:      false,
		UseChecksumVerify:     false,
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile("vps_sync_config.json", data, 0644)
	fmt.Println("已创建示例配置文件: vps_sync_config.json")
	fmt.Println("要启用镜像同步，请将配置文件中的 mirror_sync 和 delete_local_files 设置为 true")
}

// manageLogFile 定期检查日志文件，如果超过maxLines，则截断文件以仅保留最新的 linesToKeep 行。
func manageLogFile(filePath string, maxLines, linesToKeep int) {
	ticker := time.NewTicker(1 * time.Minute) // 每分钟检查一次
	defer ticker.Stop()

	for range ticker.C {
		file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			log.Printf("无法打开日志文件进行管理 %s: %v", filePath, err)
			continue
		}

		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		if len(lines) > maxLines {
			log.Printf("日志文件 %s 超过 %d 行，开始截断", filePath, maxLines)

			// 计算要保留的行的起始位置
			start := 0
			if len(lines) > linesToKeep {
				start = len(lines) - linesToKeep
			}
			
			// 获取要保留的行
			linesToRetain := lines[start:]

			// 重置文件指针到开头并清空文件
			file.Seek(0, 0)
			file.Truncate(0)

			writer := bufio.NewWriter(file)
			for _, line := range linesToRetain {
				fmt.Fprintln(writer, line)
			}
			writer.Flush()
			log.Printf("成功截断日志文件 %s，保留了 %d 行", filePath, len(linesToRetain))
		}
		file.Close()
	}
}

func main() {
	// 检查是否已有实例在运行
	if !checkSingleInstance() {
		showMessageBox("VPS同步工具", "程序已经在运行中！\n请检查系统托盘或任务管理器。")
		return
	}

	// 启动时重写日志文件
	logFile, err := os.OpenFile("out.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Panic("无法打开日志文件:", err)
	}
	// 同时输出到文件和控制台进行调试
	log.SetOutput(io.MultiWriter(logFile, os.Stdout))

	errFile, err := os.OpenFile("error.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Panic("无法打开错误日志文件:", err)
	}
	defer errFile.Close()

	// 将标准错误重定向到错误文件
	os.Stderr = errFile

	// 隐藏控制台窗口 - 临时注释调试用
	// hideConsoleWindow()

	// 启动日志文件管理器
	go manageLogFile("out.txt", 10000, 5000) // 保留最新的 5000 行
	go manageLogFile("error.txt", 10000, 5000) // 保留最新的 5000 行

	var configPath = flag.String("config", "vps_sync_config.json", "配置文件路径")
	var createConfig = flag.Bool("create-config", false, "创建示例配置文件")
	flag.Parse()

	if *createConfig {
		createSampleConfig()
		return
	}


	sync, err := NewVPSSync(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := sync.Start(); err != nil {
		log.Fatal(err)
	}

	// 等待中断信号
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	sync.Stop()
}
