package main

import (
	"bufio"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	_ "github.com/ethereum/go-ethereum/log"
	_ "github.com/ethereum/go-ethereum/metrics"
	_ "github.com/ethereum/go-ethereum/rpc"
)

func createNewAccount(ks *keystore.KeyStore, hashPassword string) (*accounts.Account, error) {
	account, err := ks.NewAccount(hashPassword)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func getKeyStore(dir string) *keystore.KeyStore {
	return keystore.NewKeyStore(dir, keystore.StandardScryptN, keystore.StandardScryptP)
}

// Перебором всех аккаунтов ищем тот который можем разблокировать
func findAccountByPassword(ks *keystore.KeyStore, hashPassword string) (*accounts.Account, error) {
	for _, account := range ks.Accounts() {
		if ks.Unlock(account, hashPassword) == nil {
			return &account, nil
		}
	}
	return nil, errors.New("account not found")
}

func main() {
	userPwd := getUserPassword()
	tmpHashUserPwd := sha256.Sum256([]byte(userPwd))
	hashUserPwd := hexutil.Encode(tmpHashUserPwd[:])

	ks := getKeyStore("./wallets")

	file, err := os.OpenFile(".tmp", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0664)
	if err != nil {
		return
	}
	defer file.Close()

	operation := defineOperation()
	if operation == "add" {
		account, err := createNewAccount(ks, hashUserPwd)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("account.Address=", account.Address)

		err = encryptToFile(tmpHashUserPwd[:], file)
		if err != nil {
			log.Fatal(err)
		}

	} else {
		account, err := findAccountByPassword(ks, hashUserPwd)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("account.Address =", account.Address)

		decryptBytes, err := decryptFromFile(file)
		if err != nil {
			log.Fatal(err)
		}

		if hexutil.Encode(decryptBytes) == hashUserPwd {
			fmt.Println("User was in file")
		}

	}

}

func encryptToFile(src []byte, direction io.Writer) error {
	cipher, err := aes.NewCipher([]byte("thisis32bitlongpassphraseimusing"))
	if err != nil {
		return err
	}
	dst16 := make([]byte, cipher.BlockSize())
	dst32 := make([]byte, cipher.BlockSize())

	cipher.Encrypt(dst16, src)
	cipher.Encrypt(dst32, src[16:])

	_, err = direction.Write(dst16)
	if err != nil {
		return err
	}
	_, err = direction.Write(dst32)
	if err != nil {
		return err
	}
	return nil
}

func decryptFromFile(reader io.Reader) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte("thisis32bitlongpassphraseimusing"))
	if err != nil {
		return nil, err
	}
	src, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	dst16 := make([]byte, cipher.BlockSize())
	dst32 := make([]byte, cipher.BlockSize())

	cipher.Decrypt(dst16, src)
	cipher.Decrypt(dst32, src[16:])

	return append(dst16, dst32...), nil
}

func defineOperation() string {
	fmt.Println("Enter operation")
	fmt.Println("[add] For create new account")
	fmt.Println("[get] For get address your account, if exist")
	reader := bufio.NewReader(os.Stdin)

	for true {
		operation, _ := reader.ReadString('\n')
		operation = strings.Trim(operation, "\n")
		if operation == "add" || operation == "get" {
			return operation
		}
		fmt.Println("Input valid operation")
	}
	return ""
}

func getUserPassword() string {
	fmt.Println("Enter your password")
	reader := bufio.NewReader(os.Stdin)

	for true {
		password, _ := reader.ReadString('\n')
		password = strings.Trim(password, "\n")
		err := checkPassword(password)
		if err == nil {
			return strings.Trim(password, " ")
		}
		fmt.Println(err)
		fmt.Println("Input valid password")
	}
	return ""
}

func checkPassword(password string) error {
	fmt.Println(len(strings.Trim(password, " ")))
	if len(strings.Trim(password, " ")) < 4 {
		return errors.New("password must be larger than 3 symbols")
	}
	return nil
}
