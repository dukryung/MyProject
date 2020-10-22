package mariadb_lib

import (
	"database/sql"
	"fmt"
	"io"
	"log"
)

const DB_RET_SUCC = 0
const DB_RET_FAIL = -1

func Connection_DB(Id string, Passwd string, DbAddr string, DbPort string, DbName string) *sql.DB {
	DbInfo := fmt.Sprintf("%s:%s@tcp(%s:%s)/", Id, Passwd, DbAddr, DbPort)

	//log.Println("SQL :", DbInfo)
	db, err := sql.Open("mysql", DbInfo)
	if err != nil {
		log.Println("SQL Open Error", err)
		panic(err)
	}
	DbInfo = fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", DbName)
	err = Create_DB(db, DbInfo)
	if err != nil {
		log.Println("Create_DB Error ", DbName)
		panic(err)
	}

	err = Choose_DB(db, DbName)
	if err != nil {
		log.Println("Create_DB Error ", DbName)
		panic(err)
	}

	return db
}

func Choose_DB(db *sql.DB, DBName string) error {
	select_db := fmt.Sprintf("USE %s", DBName)
	_, err := db.Exec(select_db)
	if err != nil {
		log.Println("db selected error:", err.Error())
		return err
	} else {
		//log.Println("db selected successfully")
		return nil
	}

	return err
}

func Create_DB(db *sql.DB, CreateSQL string) error {
	_, err := db.Exec(CreateSQL)
	if err != nil {
		log.Println("db create error:", err.Error())
		return err
	} else {
		//log.Println("db created successfully")
		return nil
	}

	return err
}

func DB_AutoCommit_Enable(db *sql.DB) error {
	var statement *sql.Stmt
	var err error

	statement, err = db.Prepare("SET AUTOCOMMIT = TRUE;")
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("auto commit enable error:", err)
		return err
	}

	_, err = statement.Exec()
	if err != nil {
		log.Println("auto commit enable error")
		return err
	}

	return nil
}

func DB_AutoCommit_Disable(db *sql.DB) error {
	var statement *sql.Stmt
	var err error

	statement, err = db.Prepare("SET AUTOCOMMIT = FALSE;")
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("auto commit disable error:", err)
		return err
	}

	_, err = statement.Exec()
	if err != nil {
		log.Println("auto commit disable error")
		return err
	}

	return nil
}

func DB_Commit(db *sql.DB) error {
	var statement *sql.Stmt
	var err error

	statement, err = db.Prepare("COMMIT;")
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("db commit error:", err)
		return err
	}

	_, err = statement.Exec()
	if err != nil {
		log.Println("db commit error")
		return err
	}

	return nil
}

func DB_Rollback(db *sql.DB) error {
	var statement *sql.Stmt
	var err error

	statement, err = db.Prepare("ROLLBACK;")
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("db commit error:", err)
		return err
	}

	_, err = statement.Exec()
	if err != nil {
		log.Println("db commit error")
		return err
	}

	return nil
}

func DB_TX_Begin(db *sql.DB) (*sql.Tx, error) {
	var tx *sql.Tx
	var err error

	tx, err = db.Begin()
	if err != nil {
		log.Println("DB Begin error:", err)
		return tx, err
	}
	return tx, nil
}

func DB_TX_Commit(tx *sql.Tx) error {
	var err error

	err = tx.Commit()
	if err != nil {
		log.Println("DB Commit error:", err)
		return err
	}

	return nil
}

func DB_TX_Rollback(tx *sql.Tx) error {
	var err error

	err = tx.Rollback()
	if err != nil {
		log.Println("DB Commit error:", err)
		return err
	}

	return nil
}

func Create_Table(db *sql.DB, TableInfo string) (int32, error) {
	var statement *sql.Stmt
	var err error

	statement, err = db.Prepare(TableInfo)
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("DCL create table error:", err)
		return DB_RET_FAIL, err
	}

	_, err = statement.Exec()
	if err != nil {
		log.Println("DCL create table error:", err)
		return DB_RET_FAIL, err
	}

	return DB_RET_SUCC, nil
}

func Insert_Data(db *sql.DB, InsertSQL string) (int64, error) {
	var statement *sql.Stmt
	var row_apply_cnt int64
	var row_ret sql.Result
	var err error

	statement, err = db.Prepare(InsertSQL)
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("insert Data error: ", err, InsertSQL)
		return DB_RET_FAIL, err
	}

	row_ret, err = statement.Exec()
	if err != nil {
		log.Println("insert execs error:", err)
		return DB_RET_FAIL, err
	}

	row_apply_cnt, err = row_ret.RowsAffected()
	if err != nil {
		log.Println("insert rows affected error:", err)
		return DB_RET_FAIL, err
	}

	//log.Println("insert db affected row count:", row_apply_cnt)
	return row_apply_cnt, nil
}

func Update_Data(db *sql.DB, UpdateSQL string) (int64, error) {
	var statement *sql.Stmt
	var row_apply_cnt int64
	var row_ret sql.Result
	var err error

	statement, err = db.Prepare(UpdateSQL)
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("update data error: ", err, UpdateSQL)
		return DB_RET_FAIL, err
	}

	row_ret, err = statement.Exec()
	if err != nil {
		log.Println("update execs error:", err)
		return DB_RET_FAIL, err
	}

	row_apply_cnt, err = row_ret.RowsAffected()
	if err != nil {
		log.Println("update rows affected error:", err)
		return DB_RET_FAIL, err
	}

	//log.Println("update db affected row count:", row_apply_cnt)
	return row_apply_cnt, nil
}

func Delete_Data(db *sql.DB, DeleteSQL string) (int64, error) {
	var statement *sql.Stmt
	var row_apply_cnt int64
	var row_ret sql.Result
	var err error

	statement, err = db.Prepare(DeleteSQL)
	defer func() {
		if statement != nil {
			statement.Close()
			statement = nil
		}
	}()

	if err != nil {
		log.Println("delete data error: ", err, DeleteSQL)
		return DB_RET_FAIL, err
	}

	row_ret, err = statement.Exec()
	if err != nil {
		log.Println("delete execs error:", err)
		return DB_RET_FAIL, err
	}

	row_apply_cnt, err = row_ret.RowsAffected()
	if err != nil {
		log.Println("delete rows affected error:", err)
		return DB_RET_FAIL, err
	}

	//log.Println("delete db affected row count:", row_apply_cnt)
	return row_apply_cnt, nil
}

func Query_DB(db *sql.DB, QuerySQL string) (*sql.Rows, error) {
	var rows *sql.Rows
	var err error

	rows, err = db.Query(QuerySQL)
	if err != nil {
		if err == io.EOF {
			log.Println("not exist row:", err)
			return rows, err
		} else {
			log.Println("query error:", err)
			return nil, err
		}
	}

	return rows, nil
}

func RowCount(db *sql.DB, CountSQL string) (int32, error) {
	var count int32
	var rows *sql.Rows
	var err error

	rows, err = Query_DB(db, CountSQL)
	defer func() {
		if rows != nil {
			rows.Close()
			rows = nil
		}
	}()

	if rows == nil {
		return DB_RET_FAIL, err
	}

	for rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			log.Println("data scan error:", err)
			return DB_RET_FAIL, err
		}
	}

	return count, nil
}
