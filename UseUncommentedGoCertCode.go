package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func main() {
	fmt.Println("hello world")
	certPool, err := loadSamSystemRoots()
	if err != nil {
		fmt.Println("error reading cert store")
	}
	if certPool != nil {
		fmt.Println("done")
	}
}

// wide returns a pointer to a a uint16 representing the equivalent
// to a Windows LPCWSTR.
func wide(s string) *uint16 {
	w := utf16.Encode([]rune(s))
	w = append(w, 0)
	return &w[0]
}

// loadSamSystemRoots does stuff
func loadSamSystemRoots() (*x509.CertPool, error) {
	// TODO: restore this functionality on Windows. We tried to do
	// it in Go 1.8 but had to revert it. See Issue 18609.
	// Returning (nil, nil) was the old behavior, prior to CL 30578.
	//return nil, nil

	const CRYPT_E_NOT_FOUND = 0x80092004
	const CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
	const certStoreProvSystem = 10 // CERT_STORE_PROV_SYSTEM
	const compareShift = 16
	const certStoreCurrentUserID = 1                                              // CERT_SYSTEM_STORE_CURRENT_USER_ID
	const certStoreLocalMachineID = 2                                             // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
	const certStoreCurrentUser = uint32(certStoreCurrentUserID << compareShift)   // CERT_SYSTEM_STORE_CURRENT_USER
	const certStoreLocalMachine = uint32(certStoreLocalMachineID << compareShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	// CERT_COMPARE_SHIFT
	// MY, CA and ROOT are well-known system stores that holds certificates.
	// The store that is opened (system or user) depends on the system call used.
	// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560(v=vs.85).aspx)
	//my := wide("MY")
	//ca := wide("CA")
	//root := wide("ROOT")

	//store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("ROOT")) // Root CAs
	//store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("CA")) // Intermediate CAs
	// THIS IS PULLING FROM THE CurrentUser MY cert store https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certopensystemstorew
	store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("MY")) // Personal Certificates
	//store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("DISALLOWED")) // Disallowed Certificates
	//store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("AUTHROOT")) // Auth Root Certificates
	//store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("ADDRESSBOOK")) // AddressBook Certificates
	//store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("TRUSTEDPEOPLE")) // Trusted People Certificates
	//store, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("TRUSTEDPUBLISHER")) // Trusted Publisher Certificates
	// store, err := syscall.CertOpenStore(
	// 	windows.CERT_STORE_PROV_SYSTEM, //CERT_STORE_PROV_SYSTEM_W
	// 	0,
	// 	0,
	// 	windows.CERT_SYSTEM_STORE_CURRENT_USER, //CERT_SYSTEM_STORE_LOCAL_MACHINE
	// 	uintptr(unsafe.Pointer(my))) // uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("MY"))))
	if err != nil {
		return nil, err
	}
	defer syscall.CertCloseStore(store, 0)

	roots := x509.NewCertPool()
	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(store, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == CRYPT_E_NOT_FOUND {
					break
				}
				fmt.Println(errno)
			}
			return nil, err
		}
		if cert == nil {
			break
		}
		// Copy the buf, since ParseCertificate does not create its own copy.
		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			//fmt.Println(c.SerialNumber)
			//fmt.Println(c.Subject)
			h := sha1.Sum(c.Raw)
			s := hex.EncodeToString(h[:])
			//b := h.Sum(nil)
			fmt.Println(s)
			//fmt.Println(c.SerialNumber)
			//fmt.Println(c.Subject)
			//fmt.Println(c.NotAfter)
			//s := string(b[:])
			//fmt.Println(s)
			//fmt.Println(c.Issuer)
			roots.AddCert(c)
		}
	}
	return roots, nil
}
