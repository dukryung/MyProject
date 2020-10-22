package mariadb_lib

import (
	"database/sql"
	"fmt"
	"io"
)

func Connection_DB(Id string, Passwd string, DbAddr string, DbPort string, DbName string) *sql.DB {
	DbInfo := fmt.Sprintf("%s:%s@tcp(%s:%s)/", Id, Passwd, DbAddr, DbPort)

	//fmt.Println("SQL :", DbInfo)
	db, err := sql.Open("mysql", DbInfo)
	if err != nil {
		fmt.Println("SQL Open Error", err)
		panic(err)
	}

	DbInfo = fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", DbName)
	err = Create_DB(db, DbInfo)
	if err != nil {
		fmt.Println("Create_DB Error ", DbName)
		panic(err)
	}

	err = Choose_DB(db, DbName)
	if err != nil {
		fmt.Println("Create_DB Error ", DbName)
		panic(err)
	}

	return db
}

func Choose_DB(db *sql.DB, DbName string) error {
	DbInfo := fmt.Sprintf("USE %s", DbName)

	_, err := db.Exec(DbInfo)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		//fmt.Println("DB selected successfully..")
	}

	return err
}

func Create_DB(db *sql.DB, CreateSQL string) error {
	_, err := db.Exec(CreateSQL)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		//fmt.Println("Successfully created database..")
	}

	return err
}

func DB_AutoCommit_Enable(db *sql.DB) {
	statement, err := db.Prepare("SET AUTOCOMMIT = TRUE;")
	if err != nil {
		fmt.Println("SET AUTOCOMMIT = TRUE error:", err)
		panic(err)
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("SET AUTOCOMMIT = TRUE Error:", err)
		panic(err)
	}
}

func DB_AutoCommit_Disable(db *sql.DB) {
	statement, err := db.Prepare("SET AUTOCOMMIT = FALSE;")
	if err != nil {
		fmt.Println("SET AUTOCOMMIT = FALSE error:", err)
		panic(err)
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("SET AUTOCOMMIT = FALSE Error:", err)
		panic(err)
	}
}

func DB_Commit(db *sql.DB) {
	statement, err := db.Prepare("commit;")
	if err != nil {
		fmt.Println("Commit error:", err)
		panic(err)
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("Commit Error:", err)
		panic(err)
	}
}

func DB_Rollback(db *sql.DB) {
	statement, err := db.Prepare("rollback;")
	if err != nil {
		fmt.Println("Rollback Prepare error:", err)
		panic(err)
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("Rollback Data Error:", err)
		panic(err)
	}
}

func Create_Table(db *sql.DB, TableInfo string) {

	statement, err := db.Prepare(TableInfo)
	if err != nil {
		fmt.Println("Create CONNECTIONS_TRAFFIC error:", err)
	}
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		fmt.Println("Create Table error:", err)
		panic(err)
	}
}

func Insert_Data(db *sql.DB, InsertSQL string) {

	statement, err := db.Prepare(InsertSQL)
	if err != nil {
		fmt.Println("Insert Data error: ", err, InsertSQL)
		panic(err)
	}
	defer statement.Close()

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
	defer statement.Close()

	_, err = statement.Exec()
	if err != nil {
		fmt.Println(">>>>>>>>>>>>>>>> Update Execs error:", err.Error())
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
	defer statement.Close()

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
			fmt.Println("Not Exist Row:", err)
		} else {
			fmt.Println("Query Error:", err)
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

