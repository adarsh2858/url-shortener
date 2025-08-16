package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

// Define structure for incoming data
type Item struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

var db *sql.DB

func initDB() {
	// Initialize database connection
	var err error
	connStr := "user=username password=password dbname=mydb sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatal("Cannot connect to database:", err)
	}
	fmt.Println("Database connected successfully.")
}

func insertData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON body
	var item Item
	err := json.NewDecoder(r.Body).Decode(&item)
	if err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	// Insert data into the database
	query := `INSERT INTO items (name, value) VALUES ($1, $2)`
	_, err = db.Exec(query, item.Name, item.Value)
	if err != nil {
		http.Error(w, "Failed to insert data", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Data inserted successfully")
}

func main() {
	initDB()

	http.HandleFunc("/insert", insertData)

	fmt.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
