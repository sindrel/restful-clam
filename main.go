/*
 * RESTful Clam by Sindre Lindstad
 * sindrelindstad.com
 */

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/gorilla/mux"
)

// UploadResult contains payload to be returned by REST API on file upload
type UploadResult struct {
	ID       string `json:"id,omitempty"`
	Error    string `json:"error,omitempty"`
	Checksum string `json:"sha256sum,omitempty"`
	Output   string `json:"output,omitempty"`
	Scanned  bool   `json:"scanned"`
	Infected bool   `json:"infected"`
}

// ScanResult is the response given after an antivirus scan has finished
type ScanResult struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Checksum string `json:"sha256sum,omitempty"`
	Error    string `json:"error,omitempty"`
	Output   string `json:"output,omitempty"`
	Infected bool   `json:"infected"`
}

// UploadBody is the body of a file upload POST request
type UploadBody struct {
	Name      string `json:"name,omitempty"`
	Base64Str string `json:"base64"`
}

// ReturnRootMessage returns the message presented when accessing /
func ReturnRootMessage(w http.ResponseWriter, r *http.Request) {
	str := "RESTful Clam!"

	w.Header().Set("Content-Type", "text/plain")
	json.NewEncoder(w).Encode(str)

	return
}

// Log is a log handler
func Log(level int, message string) {
	levelText := "DEBUG"

	if level == 1 {
		levelText = "ERROR"
	}
	if level == 2 {
		levelText = "WARN"
	}
	if level == 3 {
		levelText = "INFO"
	}
	if level == 4 {
		levelText = "DEBUG"
	}

	log.Println(levelText + " " + message)
}

// ValidateBase64Str checks if a given string is a valid base64 encoded string
func ValidateBase64Str(str string) bool {
	valid := true
	content, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		Log(3, "Base64 string invalid: "+err.Error())
		Log(4, "String: "+string(content))
		valid = false
	}
	return valid
}

// DecodeBase64Str decodes a base64 encoded string
func DecodeBase64Str(str string) []byte {
	content, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return content
}

// GenerateUUID generates a unique identifier
func GenerateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		Log(1, "Unable to generate random UUID string: "+err.Error())
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return uuid
}

// GenerateChecksum generates a sha256sum from file
func GenerateChecksum(file string) string {
	f, err := os.Open(file)
	if err != nil {
		Log(1, "Unable to open file: "+err.Error())
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		Log(1, "Unable to generate sha256 checksum: "+err.Error())
		return ""
	}

	Log(3, "File checksum: "+hex.EncodeToString(h.Sum(nil)))
	return hex.EncodeToString(h.Sum(nil))
}

// ScanPath scans a file path
func ScanPath(path string) (int, string) {
	maxTimeout := "180"

	// Execute clamscan
	cmd := exec.Command("timeout", "-t", maxTimeout, "clamdscan", path)
	stdout, err := cmd.Output()

	if err != nil {
		if err.Error() == "exit status 1" { // File is infected
			return 1, string(stdout)
		}

		if err.Error() == "exit status 2" {
			Log(4, err.Error())
			return 2, ""
		}

		if (err.Error() == "exit status 124") || (err.Error() == "exit status 127") {
			Log(4, err.Error())
			return 3, ""
		}
	}

	return 0, ""
}

// GetBaseDir fetches the current base directory path
func GetBaseDir() string {
	baseDirPath := "/tmp" // Default
	if baseDir := os.Getenv("DATA_DIR"); baseDir != "" {
		baseDirPath = baseDir
	}

	return baseDirPath
}

// UploadFileBase64 handles incoming base64 encoded files
func UploadFileBase64(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var output UploadResult

	folder := GetBaseDir() + "/files"
	folderMeta := GetBaseDir() + "/metadata"

	Log(3, "Received base64 encoded file")

	dec := json.NewDecoder(r.Body)
	var uploadedFile UploadBody
	for {
		if err := dec.Decode(&uploadedFile); err == io.EOF {
			break
		} else if err != nil {
			Log(1, "Unable to parse request body: "+err.Error())
		}
	}

	decoded := DecodeBase64Str(string([]byte(uploadedFile.Base64Str)))

	if !ValidateBase64Str(string([]byte(uploadedFile.Base64Str))) {
		http.Error(w, "Base64 decoding failed", http.StatusBadRequest)
		return
	}

	fileID := GenerateUUID()
	path := folder + "/" + fileID + ".tmp"
	pathMeta := folderMeta + "/" + fileID + ".tmp"

	Log(3, "Saving file: "+path)
	err := ioutil.WriteFile(path, decoded, 0644)
	if err != nil {
		Log(1, "Unable to save file: "+err.Error())
		http.Error(w, "Unable to save file "+path, http.StatusBadRequest)
		return
	}

	Log(4, "Saving metadata file: "+pathMeta)
	err = ioutil.WriteFile(pathMeta, []byte(uploadedFile.Name), 0644)
	if err != nil {
		Log(1, "Unable to save metadata file: "+err.Error())
		http.Error(w, "Unable to save metadata file "+pathMeta, http.StatusBadRequest)
		return
	}

	checksum := GenerateChecksum(path)
	if checksum == "" {
		http.Error(w, "Unable to generate file checksum", http.StatusBadRequest)
		return
	}

	output.ID = fileID
	output.Checksum = checksum
	output.Scanned = false
	output.Infected = false

	if params["scan"] == "true" {
		output.Scanned = true

		scanCode, scanOut := ScanPath(path)

		if scanCode == 1 {
			output.Infected = true
			output.Output = scanOut
			os.Remove(path)
		} else if scanCode > 1 {
			http.Error(w, "Unable to scan file", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)

	return
}

// UploadFileForm handles incoming form posted files
func UploadFileForm(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var output UploadResult
	folder := GetBaseDir() + "/files"
	folderMeta := GetBaseDir() + "/metadata"

	Log(3, "Received multi-part/formdata file")

	r.ParseMultipartForm(10 << 20)
	file, handler, err := r.FormFile("file")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		return
	}
	defer file.Close()

	fileID := GenerateUUID()
	path := folder + "/" + fileID + ".tmp"
	pathMeta := folderMeta + "/" + fileID + ".tmp"

	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}

	Log(3, "Saving file: "+path)
	err = ioutil.WriteFile(path, fileContent, 0644)
	if err != nil {
		Log(1, "Unable to save file: "+err.Error())
		http.Error(w, "Unable to save file "+path, http.StatusBadRequest)
		return
	}

	Log(4, "Saving metadata file: "+pathMeta)
	err = ioutil.WriteFile(pathMeta, []byte(handler.Filename), 0644)
	if err != nil {
		Log(1, "Unable to save metadata file: "+err.Error())
		http.Error(w, "Unable to save metadata file "+pathMeta, http.StatusBadRequest)
		return
	}

	checksum := GenerateChecksum(path)
	if checksum == "" {
		http.Error(w, "Unable to generate file checksum", http.StatusBadRequest)
		return
	}

	output.ID = fileID
	output.Checksum = checksum
	output.Scanned = false
	output.Infected = false

	if params["scan"] == "true" {
		output.Scanned = true

		scanCode, scanOut := ScanPath(path)

		if scanCode == 1 {
			output.Infected = true
			output.Output = scanOut
			os.Remove(path)
		} else if scanCode > 1 {
			http.Error(w, "Unable to scan file", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)

	return
}

// ScanFile scans a path and returns a result
func ScanFile(w http.ResponseWriter, r *http.Request) {
	var output ScanResult
	params := mux.Vars(r)
	folder := GetBaseDir() + "/files"
	folderMeta := GetBaseDir() + "/metadata"

	path := folder + "/" + params["id"] + ".tmp"
	pathMeta := folderMeta + "/" + params["id"] + ".tmp"

	// Scan all files in folder
	if params["id"] == "all" {
		path = folder
	}

	Log(3, "Scanning path: "+path)

	checksum := ""
	if params["id"] != "all" {
		checksum = GenerateChecksum(path)
		if checksum == "" {
			http.Error(w, "Unable to generate file checksum - does the file still exist?", http.StatusBadRequest)
			return
		}
	}

	output.ID = params["id"]
	output.Infected = false
	output.Checksum = checksum

	scanCode, scanOut := ScanPath(path)

	if scanCode == 1 {
		output.Infected = true
		output.Output = scanOut
	}

	if scanCode == 2 {
		http.Error(w, "The ClamAV daemon is not ready (yet) - please wait", http.StatusBadRequest)
		return
	}

	if scanCode == 3 {
		http.Error(w, "Clamscan execution failed", http.StatusBadRequest)
		return
	}

	if output.Infected == false {
		Log(3, "File(s) clean")
	} else {
		Log(3, "Found infected file(s)!")
	}

	// Get filename from metadata
	if params["id"] != "all" {
		fileMetadata, err := os.Open(pathMeta)
		if err != nil {
			Log(2, "Unable to fetch metadata: "+err.Error())
		}
		defer fileMetadata.Close()

		fileMetadataName, err := ioutil.ReadAll(fileMetadata)
		output.Name = string(fileMetadataName)
	}

	// Remove file or empty folder
	if params["id"] == "all" {
		os.RemoveAll(folder)
		os.MkdirAll(folder, 0755)
	} else {
		os.Remove(path)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)

	return
}

// UpdateDatabases updates the ClamAV virus database
func UpdateDatabases(w http.ResponseWriter, r *http.Request) {
	maxTimeout := "600"

	Log(3, "Virus database update requested - running freshclam")

	// Execute freshclam
	cmd := exec.Command("timeout", "-t", maxTimeout, "freshclam")

	stdout, err := cmd.Output()
	Log(3, string(stdout))

	if err != nil {
		if err.Error() == "exit status 1" {
			Log(3, "Virus databases up-to-date")
			w.WriteHeader(http.StatusOK)
			return
		}

		Log(1, "Virus database update failed")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	Log(3, "Virus database update finished")
	w.WriteHeader(http.StatusOK)
	return
}

// HealthCheckReadynessProbe checks if the ClamAV daemon is ready and working
func HealthCheckReadynessProbe(w http.ResponseWriter, r *http.Request) {
	scanCode, scanOut := ScanPath("/tmp/eicar.txt")

	if scanCode == 1 {
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Health check failed: "+scanOut, http.StatusBadRequest)
	return
}

// DeleteFile deletes a file
func DeleteFile(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	folder := GetBaseDir() + "/files"

	path := folder + "/" + params["id"] + ".tmp"
	err := os.Remove(path)

	if err != nil {
		Log(1, "File deletion failed")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	Log(3, "File deleted")
	w.WriteHeader(http.StatusOK)
	return
}

// ServeSwaggerUI serves the static Swagger UI pages
func ServeSwaggerUI(router *mux.Router, pathPrefix string) {
	router.PathPrefix(pathPrefix).Handler(http.StripPrefix(pathPrefix,
		http.FileServer(http.Dir("/static/swaggerui/"))))
}

func main() {
	Log(3, "Server started")

	contextPath := ""
	if apiContextPath := os.Getenv("API_CONTEXT_PATH"); apiContextPath != "" {
		contextPath = apiContextPath
	}

	router := mux.NewRouter()
	ServeSwaggerUI(router, "/swaggerui")
	router.HandleFunc(contextPath+"/", ReturnRootMessage).Methods("GET")
	router.HandleFunc(contextPath+"/api/v1", ReturnRootMessage).Methods("GET")

	router.HandleFunc(contextPath+"/api/v1/file/base64", UploadFileBase64).Methods("POST").Queries("scan", "{scan:[a-z]+}")
	router.HandleFunc(contextPath+"/api/v1/file/base64", UploadFileBase64).Methods("POST")
	// swagger:operation POST /api/v1/file/base64 files uploadFileBase64
	// ---
	// summary: Uploads a base64 encoded file
	// description: Uploads a base64 encoded file in a JSON formatted request body. Returns checksum and ID on successful file transfer.
	// consumes:
	//   - application/json
	// parameters:
	//   - in: body
	//     name: file
	//     description: The file to upload. Specifying a name is optional, but recommended.
	//     schema:
	//       type: object
	//       properties:
	//         base64:
	//           type: string
	//         name:
	//           type: string
	//       example:
	//         base64: WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK
	//         name: eicar.txt
	//   - in: query
	//     name: scan
	//     description: Scan instantly after upload
	//     type: boolean
	//     required: false
	//     example:
	//       scan: true
	// responses:
	//   "200":
	//     "OK"
	//   "400":
	//     "Something went wrong"

	router.HandleFunc(contextPath+"/api/v1/file/form", UploadFileForm).Methods("POST").Queries("scan", "{scan:[a-z]+}")
	router.HandleFunc(contextPath+"/api/v1/file/form", UploadFileForm).Methods("POST")
	// swagger:operation POST /api/v1/file/form files uploadFileForm
	// ---
	// summary: Uploads a file using form-data
	// description: Uploads a file using multipart/form-data. Returns checksum and ID on successful file transfer.
	// consumes:
	//   - multipart/form-data
	// parameters:
	//   - in: formData
	//     name: file
	//     type: file
	//     description: The file to upload
	//   - in: query
	//     name: scan
	//     description: Scan instantly after upload
	//     type: boolean
	//     required: false
	//     example:
	//       scan: true
	// responses:
	//   "200":
	//     "OK"
	//   "400":
	//     "Something went wrong"

	router.HandleFunc(contextPath+"/api/v1/scan/{id}", ScanFile).Methods("GET")
	// swagger:operation GET /api/v1/scan/{id} scanning scanFile
	// ---
	// summary: Scans a single file
	// description: Scans a file, identified by ID. By default, the file will be deleted after being scanned.
	// parameters:
	// - name: id
	//   in: path
	//   description: File ID (UUID)
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "OK"
	//   "400":
	//     "Something went wrong"

	router.HandleFunc(contextPath+"/api/v1/scan/all", ScanFile).Methods("GET")
	// swagger:operation GET /api/v1/scan/all scanning scanAllFiles
	// ---
	// summary: Scans all files
	// description: Scans all unscanned files. By default all files will be deleted after being scanned.
	// responses:
	//   "200":
	//     "OK"
	//   "400":
	//     "Something went wrong"

	router.HandleFunc(contextPath+"/api/v1/file/{id}", DeleteFile).Methods("DELETE")
	// swagger:operation DELETE /api/v1/file/{id} files deleteFile
	// ---
	// summary: Deletes a file
	// description: Deletes an unscanned file.
	// parameters:
	// - name: id
	//   in: path
	//   description: File ID (UUID)
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     "OK"
	//   "400":
	//     "Something went wrong"

	router.HandleFunc(contextPath+"/api/v1/database/update", UpdateDatabases).Methods("POST")
	// swagger:operation POST /api/v1/database/update databases updateDatabases
	// ---
	// summary: Updates virus definition databases
	// description: Updates virus databases using freshclam
	// responses:
	//   "200":
	//     "OK"
	//   "400":
	//     "Something went wrong"

	router.HandleFunc(contextPath+"/api/v1/health/ready", HealthCheckReadynessProbe).Methods("GET")
	// swagger:operation GET /api/v1/health/ready health healthReady
	// ---
	// summary: Readyness probe
	// description: Checks if the ClamAV daemon is ready and responding.
	// responses:
	//   "200":
	//     "Ready"
	//   "400":
	//     "Not ready"

	port := ":8080"
	if apiPort := os.Getenv("API_PORT"); apiPort != "" {
		port = ":" + apiPort
	}

	log.Fatal(http.ListenAndServe(port, router))
}
