package utils

import "wing/pkg/secure"

// GetMachineID 获取机器唯一标识，用于生成本地加密密钥
func GetMachineID() string {
	return secure.GetMachineID()
}

// DeriveKey 从机器 ID 生成 32 字节 AES 密钥
func DeriveKey() []byte {
	return secure.DeriveKey()
}

// EncryptData 使用 AES-GCM 加密数据
func EncryptData(data []byte) ([]byte, error) {
	return secure.EncryptData(data)
}

// DecryptData 使用 AES-GCM 解密数据
func DecryptData(data []byte) ([]byte, error) {
	return secure.DecryptData(data)
}

// MagicHeader 用于识别文件是否已加密
const MagicHeader = secure.MagicHeader

// SecureWriteFile 安全地写入加密文件
func SecureWriteFile(filename string, data []byte) error {
	return secure.SecureWriteFile(filename, data)
}

// SecureReadFile 安全地读取并解密文件，如果未加密则返回原内容（兼容性）
func SecureReadFile(filename string) ([]byte, error) {
	return secure.SecureReadFile(filename)
}
