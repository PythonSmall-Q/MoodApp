import type { D1Database, D1DatabaseSession } from '@cloudflare/workers-types';
import { Result, ThrowErrorIfFailed } from './Result';
import { Output } from './Output';

let readonly = false; // set to true to allow maintenance

export class Database {
  private RawDatabase: D1DatabaseSession;

  constructor(RawDatabase: D1Database) {
    this.RawDatabase = RawDatabase.withSession();
  }

  // Execute arbitrary SQL (SELECT/UPDATE/INSERT/DELETE). Returns raw D1 result (results + meta).
  public async Query(QueryString: string, BindData: any[] = []): Promise<Result> {
    Output.Debug("Executing SQL query:\n" +
      "    Query    : \"" + QueryString + "\"\n" +
      "    Arguments: " + JSON.stringify(BindData) + "\n");
    try {
      const stmt = this.RawDatabase.prepare(QueryString);
      const SQLResult = await (BindData.length > 0 ? stmt.bind(...BindData) : stmt).all();
      Output.Debug("SQL query returned with result: \n" +
        "    Result: \"" + JSON.stringify(SQLResult) + "\"\n");
      return new Result(true, "数据库查询成功", SQLResult);
    } catch (ErrorDetail) {
      Output.Warn("Error while executing SQL query: \n" +
        "    Query    : \"" + QueryString + "\"\n" +
        "    Arguments: " + JSON.stringify(BindData) + "\n" +
        "    Error    : \"" + ErrorDetail);
      return new Result(false, "数据库查询失败：" + String(ErrorDetail));
    }
  }

  // Transaction helpers using this session
  public async BeginImmediate(): Promise<void> {
    await this.RawDatabase.prepare("BEGIN IMMEDIATE;").run();
  }
  public async Commit(): Promise<void> {
    await this.RawDatabase.prepare("COMMIT;").run();
  }
  public async Rollback(): Promise<void> {
    await this.RawDatabase.prepare("ROLLBACK;").run();
  }

  public async Insert(Table: string, Data: Record<string, any>): Promise<Result> {
    if (readonly) {
      return new Result(false, "数据库只读模式，无法写入");
    }
    let QueryString = "INSERT INTO `" + Table + "` (";
    for (const i in Data) {
      QueryString += "`" + i + "`, ";
    }
    QueryString = QueryString.substring(0, QueryString.length - 2);
    QueryString += ") VALUES (";
    const BindData: any[] = [];
    for (const i in Data) {
      QueryString += "?, ";
      BindData.push(Data[i]);
    }
    QueryString = QueryString.substring(0, QueryString.length - 2);
    QueryString += ");";
    const res = await this.Query(QueryString, BindData);
    const meta = (ThrowErrorIfFailed(res) as any).meta || {};
    return new Result(true, "数据库插入成功", { InsertID: meta.last_row_id });
  }

  public async Select(Table: string, Data: string[] = [], Condition?: Record<string, any>, Other?: any, Distinct?: boolean): Promise<Result> {
    let QueryString = "SELECT ";
    if (Distinct) QueryString += "DISTINCT ";
    if (!Data || Data.length === 0) {
      QueryString += "*";
    } else {
      for (const i of Data) {
        QueryString += "`" + i + "`, ";
      }
      QueryString = QueryString.substring(0, QueryString.length - 2);
    }
    QueryString += " FROM `" + Table + "`";
    const BindData: any[] = [];
    if (Condition !== undefined && Condition !== null) {
      QueryString += " WHERE ";
      for (const k in Condition) {
        if (typeof Condition[k] != "object") {
          QueryString += "`" + k + "` = ? AND ";
          BindData.push(Condition[k]);
        } else {
          QueryString += "`" + k + "` " + Condition[k]["Operator"] + " ? AND ";
          BindData.push(Condition[k]["Value"]);
        }
      }
      QueryString = QueryString.substring(0, QueryString.length - 5);
    }
    if (Other !== undefined && Other !== null) {
      if ((Other["Order"] !== undefined && Other["OrderIncreasing"] === undefined) || (Other["Order"] === undefined && Other["OrderIncreasing"] !== undefined)) {
        return new Result(false, "排序关键字和排序顺序必须同时定义或非定义");
      }
      if (Other["Order"] !== undefined && Other["OrderIncreasing"] !== undefined) {
        QueryString += " ORDER BY `" + Other["Order"] + "` " + (Other["OrderIncreasing"] ? "ASC" : "DESC");
      }
      if (Other["Limit"] !== undefined) {
        QueryString += " LIMIT " + Other["Limit"];
      }
      if (Other["Offset"] !== undefined) {
        QueryString += " OFFSET " + Other["Offset"];
      }
    }
    QueryString += ";";
    const res = await this.Query(QueryString, BindData);
    return new Result(true, "数据库查找成功", (ThrowErrorIfFailed(res) as any).results);
  }

  public async Update(Table: string, Data: Record<string, any>, Condition?: Record<string, any>): Promise<Result> {
    if (readonly) {
      return new Result(false, "数据库只读模式，无法写入");
    }
    let QueryString = "UPDATE `" + Table + "` SET ";
    const BindData: any[] = [];
    for (const i in Data) {
      QueryString += "`" + i + "` = ?, ";
      BindData.push(Data[i]);
    }
    QueryString = QueryString.substring(0, QueryString.length - 2);
    if (Condition !== undefined && Condition !== null) {
      QueryString += " WHERE ";
      for (const i in Condition) {
        if (typeof Condition[i] != "object") {
          QueryString += "`" + i + "` = ? AND ";
          BindData.push(Condition[i]);
        } else {
          QueryString += "`" + i + "` " + Condition[i]["Operator"] + " ? AND ";
          BindData.push(Condition[i]["Value"]);
        }
      }
      QueryString = QueryString.substring(0, QueryString.length - 5);
    }
    QueryString += ";";
    const res = await this.Query(QueryString, BindData);
    const meta = (ThrowErrorIfFailed(res) as any).meta || {};
    return new Result(true, "数据库更新成功", { meta });
  }

  public async GetTableSize(Table: string, Condition?: Record<string, any>): Promise<Result> {
    let QueryString = "SELECT COUNT(*) AS count FROM `" + Table + "`";
    const BindData: any[] = [];
    if (Condition !== undefined && Condition !== null) {
      QueryString += " WHERE ";
      for (const i in Condition) {
        if (typeof Condition[i] != "object") {
          QueryString += "`" + i + "` = ? AND ";
          BindData.push(Condition[i]);
        } else {
          QueryString += "`" + i + "` " + Condition[i]["Operator"] + " ? AND ";
          BindData.push(Condition[i]["Value"]);
        }
      }
      QueryString = QueryString.substring(0, QueryString.length - 5);
    }
    QueryString += ";";
    const res = await this.Query(QueryString, BindData);
    const first = (ThrowErrorIfFailed(res) as any).results?.[0];
    return new Result(true, "数据库获得大小成功", { TableSize: first?.count ?? 0 });
  }

  public async Delete(Table: string, Condition?: Record<string, any>): Promise<Result> {
    if (readonly) {
      return new Result(false, "数据库只读模式，无法写入");
    }
    let QueryString = "DELETE FROM `" + Table + "`";
    const BindData: any[] = [];
    if (Condition !== undefined && Condition !== null) {
      QueryString += " WHERE ";
      for (const i in Condition) {
        if (typeof Condition[i] != "object") {
          QueryString += "`" + i + "` = ? AND ";
          BindData.push(Condition[i]);
        } else {
          QueryString += "`" + i + "` " + Condition[i]["Operator"] + " ? AND ";
          BindData.push(Condition[i]["Value"]);
        }
      }
      QueryString = QueryString.substring(0, QueryString.length - 5);
    }
    QueryString += ";";
    const res = await this.Query(QueryString, BindData);
    const meta = (ThrowErrorIfFailed(res) as any).meta || {};
    return new Result(true, "数据库删除成功", { meta });
  }
}
