package sqlitedb_lib

import (
	"database/sql"
	"fmt"
	"io"
	"log"
)

func Create_DB(DbName string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", DbName)
	if err != nil {
		fmt.Println("Create_DB Error", err)
		panic(err.Error())
	}
	return db, nil
}

func Create_Table(db *sql.DB, TableInfo string) {
	statement, err := db.Prepare(TableInfo)
	if err != nil {
		fmt.Println("Create CONNECTIONS_TRAFFIC error:", err)
	}
	statement.Exec()
}

func Drop_Table(db *sql.DB, TableName string) {
	QueryStr := fmt.Sprintf("DROP TABLE IF EXISTS %s", TableName)

	statement, err := db.Prepare(QueryStr)
	if err != nil {
		fmt.Println("Drop %s error:", TableName, err)
	}
	statement.Exec()
}

func Insert_Data(db *sql.DB, InsertSQL string) {
	statement, err := db.Prepare(InsertSQL)
	if err != nil {
		fmt.Println("Insert Data error: ", err, InsertSQL)
		panic(err)
	}

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("Insert Execs error:", err)
		panic(err)
	}
}

func Update_Data(db *sql.DB, UpdateSQL string) {
	statement, err := db.Prepare(UpdateSQL)
	if err != nil {
		fmt.Println("Update Data error: ", err, UpdateSQL)
		panic(err)
	}

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("Update Execs error:", err)
		panic(err)
	}
}

func Delete_Data(db *sql.DB, DelSQL string) {
	statement, err := db.Prepare(DelSQL)
	if err != nil {
		fmt.Println("Delete Prepare error:", err)
		panic(err)
	}

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("Delete Data Error:", err)
		panic(err)
	}
}

func Query_DB(db *sql.DB, QuerySQL string) (rows *sql.Rows) {
	rows, err := db.Query(QuerySQL)
	if err != nil {
		if err == io.EOF {
			log.Println("Not Exist Row:", err)
		} else {
			log.Println("Query Error:", err)
			panic(err)
		}
	}

	return rows
}

func RowCount(db *sql.DB, TableName string) int {
	var Count int

	QueryStr := fmt.Sprintf("SELECT COUNT(*) FROM %s", TableName)
	Rows := Query_DB(db, QueryStr)
	for Rows.Next() {
		err := Rows.Scan(&Count)
		if err != nil {
			fmt.Println(" data Scan error:", err)
			panic(err)
		}
	}

	return Count
}
