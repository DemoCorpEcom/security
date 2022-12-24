package main

import (
  	"encoding/json"
  	"fmt"
	"os/exec"
	"net/http"
	
)

type Info struct {
	Name        string   `json:"name"`
	Author      []string `json:"author"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
	Reference   interface{} `json:"reference"`
	Severity    string  `json:"severity"`
}

type Data struct {
	TemplateID string `json:"template-id"`
	Info       Info   `json:"info"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	IP         string `json:"ip"`
	Timestamp  string `json:"timestamp"`
	Curl       string `json:"curl-command"`
	Status     bool   `json:"matcher-status"`
	Line       string `json:"matched-line"`
}

var tempEngine string

var vulnerability string

func setTempEngine(newValue string) {
	tempEngine = newValue
}

func setVulnerability(newValue string){

	vulnerability:=newValue

	switch vulnerability{
	case "/sqli":
		setTempEngine("./sqli-template.yaml")
	}

}

func main() {
	http.HandleFunc("/", httpReqestHandler)
	http.ListenAndServe(":3000", nil)
}


func httpReqestHandler(w http.ResponseWriter, r *http.Request) {

	url:="http://localhost/product.php?id=1"

	path := r.URL.Path

	setVulnerability(path)

	
	cmd:=exec.Command("nuclei","-u",url,"-t",tempEngine,"-silent","-json")
	data,err:=cmd.Output()
	if err != nil {
		fmt.Printf("Error running command: %s\n", err)
		return
	}
	
	if(len(data)==0){
		fmt.Fprintf(w, "<h1>No vulnerability detected</h1>\n")
		return
	}
	
	var result Data
	err1 := json.Unmarshal([]byte(data), &result)
	
	if err1 != nil {
		fmt.Println("Error:", err1)
		return
	}

	fmt.Fprintf(w, "<h1>Vulnerability Detected!!</h1>\n")
	fmt.Fprintf(w, "<b>Name:</b> %s </br>",result.Info.Name)
	fmt.Fprintf(w, "<b>Description:</b> %s</br>", result.Info.Description)
	fmt.Fprintf(w, "<b>Severity:</b> %s</br>", result.Info.Severity)
	fmt.Fprintf(w, "<b>Host:</b> %s</br>", result.Host)
	fmt.Fprintf(w, "<b>MatchedAt:</b> %s</br>", result.MatchedAt)
	fmt.Fprintf(w, "<b>Timestamp:</b> %s</br>", result.Timestamp)
}