package mariadb_lib

import (
	"database/sql"
	"fmt"
	"io"
	"log"
)

const DB_RET_SUCC = 0
const DB_RET_FAIL = -1

func Connection_DB(Id string, Passwd string, DbAddr string, DbPort string, DbName string) (*sql.DB, error) {
	DbInfo := fmt.Sprintf("%s:%s@tcp(%s:%s)/", Id, Passwd, DbAddr, DbPort)

	//log.Println("SQL :", DbInfo)
	db, err := sql.Open("mysql", DbInfo)
	if err != nil {
		log.Println("SQL Open Error", err)
		return nil, err
	}

	DbInfo = fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", DbName)
	err = Create_DB(db, DbInfo)
	if err != nil {
		log.Println("Create_DB Error ", DbName)
		return nil, err
	}

	err = Choose_DB(db, DbName)
	if err != nil {
		log.Println("Create_DB Error ", DbName)
		return nil, err
	}

	return db, nil
}

func Choose_DB(db *sql.DB, DbName string) error {
	DbInfo := fmt.Sprintf("USE %s", DbName)

	_, err := db.Exec(DbInfo)
	if err != nil {
		log.Println(err.Error())
	} else {
		log.Println("DB selected successfully..")
	}

	return err
}

func Create_DB(db *sql.DB, CreateSQL string) error {
	_, err := db.Exec(CreateSQL)
	if err != nil {
		log.Println(err.Error())
	} else {
		log.Println("Successfully created database..")
	}

	return err
}

func Create_Table(db *sql.DB, TableInfo string) (int32, error) {
	var statement *sql.Stmt
	var err error

	statement, err = db.Prepare(TableInfo)
	defer func() {
		if statement != nil {
			statement.Close()
		}
	}()

	if err != nil {
		log.Println("Create CONNECTIONS_TRAFFIC error:", err)
		return DB_RET_FAIL, err
	}

	_, err = statement.Exec()
	if err != nil {
		log.Println("Create Table error:", err)
		return DB_RET_FAIL, err
	}

	return DB_RET_SUCC, nil
}

func Insert_Data(db *sql.DB, InsertSQL string) (int64, error) {
	var statement *sql.Stmt
	var err error
	var col_cnt int64
	var res sql.Result

	statement, err = db.Prepare(InsertSQL)
	defer func() {
		if statement != nil {
			statement.Close()
		}
	}()

	if err != nil {
		log.Println("Insert Data error: ", err, InsertSQL)
		return DB_RET_FAIL, err
	}

	res, err = statement.Exec()
	if err != nil {
		log.Println("Insert Execs error:", err)
		return DB_RET_FAIL, err
	}
	col_cnt, err = res.RowsAffected()
	if err != nil {
		log.Println("Rows Affected error:", err)
		return DB_RET_FAIL, err
	}

	//log.Println("Insert DB Affected column count:", col_cnt)

	return col_cnt, nil

}

func Update_Data(db *sql.DB, UpdateSQL string) (int64, error) {
	var statement *sql.Stmt
	var err error
	var col_cnt int64
	var res sql.Result

	statement, err = db.Prepare(UpdateSQL)
	defer func() {
		if statement != nil {
			statement.Close()
		}
	}()

	if err != nil {
		log.Println("Update Data error: ", err, UpdateSQL)
		return DB_RET_FAIL, err
	}

	res, err = statement.Exec()
	if err != nil {
		log.Println("Update Execs error:", err)
		return DB_RET_FAIL, err
	}

	col_cnt, err = res.RowsAffected()
	if err != nil {
		log.Println("Rows Affected error:", err)
		return DB_RET_FAIL, err
	}

	log.Println("Update DB Affected column count:", col_cnt)

	return col_cnt, nil

}

func Delete_Data(db *sql.DB, DelSQL string) (int64, error) {
	var statement *sql.Stmt
	var err error
	var col_cnt int64
	var res sql.Result

	statement, err = db.Prepare(DelSQL)
	defer func() {
		if statement != nil {
			statement.Close()
		}
	}()

	if err != nil {
		log.Println("Delete Prepare error:", err)
		return DB_RET_FAIL, err
	}

	res, err = statement.Exec()
	if err != nil {
		log.Println("Delete Data Error:", err)
		return DB_RET_FAIL, err
	}

	col_cnt, err = res.RowsAffected()
	if err != nil {
		log.Println("Rows Affected error:", err)
		return DB_RET_FAIL, err
	}

	log.Println("Delete DB Affected column count:", col_cnt)

	return col_cnt, nil

}
func DB_Auto_Commit_Enable(db *sql.DB) error {
	var stmt *sql.Stmt
	var err error
	stmt, err = db.Prepare("SET AUTOCOMMIT = TRUE;")
	defer func() {
		if stmt != nil {
			stmt.Close()
		}
	}()
	if err != nil {
		log.Println("Prepare stmt error:", err)
		return err
	}
	_, err = stmt.Exec()
	if err != nil {
		log.Println("stmt.Exec error")
		return err
	}

	return nil
}

func DB_Auto_Commit_Disable(db *sql.DB) error {
	var stmt *sql.Stmt
	var err error

	stmt, err = db.Prepare("SET AUTOCOMMIT = FALSE;")
	defer func() {
		if stmt != nil {
			stmt.Close()
		}
	}()
	if err != nil {
		log.Println("Prepare stmt error:", err)
		return err
	}
	_, err = stmt.Exec()
	if err != nil {
		log.Println("stmt.Exec error")
		return err
	}

	return nil
}
func DB_Rollback_SQL(db *sql.DB) error {
	var stmt *sql.Stmt
	var err error

	stmt, err = db.Prepare("ROLLBACK;")
	defer func() {
		if stmt != nil {
			stmt.Close()
		}
	}()
	if err != nil {
		log.Println("Prepare stmt error:", err)
		return err
	}
	_, err = stmt.Exec()
	if err != nil {
		log.Println("stmt.Exec error")
		return err
	}

	return nil
}
func DB_Commit_SQL(db *sql.DB) error {
	var stmt *sql.Stmt
	var err error

	stmt, err = db.Prepare("COMMIT;")
	defer func() {
		if stmt != nil {
			stmt.Close()
		}
	}()
	if err != nil {
		log.Println("Prepare stmt error:", err)
		return err
	}
	_, err = stmt.Exec()
	if err != nil {
		log.Println("stmt.Exec error")
		return err
	}

	return nil
}

func DB_Exec(tx *sql.Tx, QuerySQL string) (int64, error) {
	var err error
	var col_cnt int64
	var res sql.Result

	res, err = tx.Exec(QuerySQL)
	if err != nil {
		log.Println("DB Exec error!", err)
		return DB_RET_FAIL, err
	}
	col_cnt, err = res.RowsAffected()
	if err != nil {
		log.Println("rows affected error:", err)
		return DB_RET_FAIL, err
	}
	log.Println("QuerySQL:", QuerySQL)
	log.Println("Affected col_cnt:", col_cnt)

	return col_cnt, nil
}

func DB_Begin(db *sql.DB) (*sql.Tx, error) {
	var tx *sql.Tx
	var err error

	tx, err = db.Begin()
	if err != nil {
		log.Println("DB Begin error:", err)
		return tx, err
	}
	return tx, nil
}

func DB_Commit(tx *sql.Tx) error {
	var err error
	err = tx.Commit()
	if err != nil {
		log.Println("DB Commit error:", err)
		return err
	}

	return nil
}

func DB_Rollback(tx *sql.Tx) {
	tx.Rollback()
}

func Query_DB(db *sql.DB, QuerySQL string) (*sql.Rows, error) {
	rows, err := db.Query(QuerySQL)
	if err != nil {
		if err == io.EOF {
			log.Println("Not Exist Row:", err)
			return rows, err
		} else {
			log.Println("Query Error:", err)
			return nil, err
		}
	}

	return rows, nil
}

func RowCount(db *sql.DB, TableName string) (int32, error) {

	var Count int32
	var Rows *sql.Rows
	var err error

	QueryStr := fmt.Sprintf("SELECT COUNT(*) FROM %s", TableName)

	Rows, err = Query_DB(db, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()

	if Rows == nil {
		return DB_RET_FAIL, err
	}

	for Rows.Next() {
		err := Rows.Scan(&Count)
		if err != nil {
			log.Println(" data Scan error:", err)
			return DB_RET_FAIL, err
		}
	}

	return Count, nil
}
