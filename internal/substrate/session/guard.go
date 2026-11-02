// Package session 提供跨层共享的会话状态校验：exec 等进入容器的操作，
// 必须先确认会话存在、处于 running 且其 lease 仍处于活跃状态。
//
// 口径：GuardExec 是执行前置条件校验（状态机检查），不是会话归属授权模型——
// 调用者身份边界由 daemon 鉴权（bearer token）承担；「哪个调用者拥有哪个
// session」的归属授权属独立的产品级特性，本包不声称提供。补上状态校验的
// 意义：仅持有会话 id（如从日志/URL 泄露）不能对停滞会话执行命令。
package session

import (
	"database/sql"
	"errors"
	"fmt"
)

// 语义化错误：HTTP/handler 层可按 errors.Is 映射 404/409；错误文本只描述会话状态，
// 不透出底层驱动细节（例如 sqlite 的 "sql: no rows in result set" 存在性 oracle）。
var (
	// ErrSessionNotFound 会话不存在 —— HTTP 语义 404 Not Found。
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionNotRunning 会话存在但未处于可执行状态（stopped/removed 或无容器）—— HTTP 语义 409 Conflict。
	ErrSessionNotRunning = errors.New("session is not running")
	// ErrLeaseInactive 会话背后的 lease 已终结或缺失 —— HTTP 语义 409 Conflict。
	ErrLeaseInactive = errors.New("session lease is no longer active")
)

// activeLeaseStatuses 是 lease 的活跃状态集合。leases 表没有过期时间字段，
// 以状态机为准：created（已创建未分配）/ allocated（已被会话占用）视为活跃；
// 其余状态（stopped/revoked/expired 等一切后续值）一律视为失效。
var activeLeaseStatuses = map[string]bool{
	"created":   true,
	"allocated": true,
}

// GuardExec 校验 sessionID 是否允许进入容器执行命令：会话必须存在且 status=running、
// 已绑定容器 id，且其 lease 处于活跃状态。任一条件不满足返回可判别的 sentinel 错误。
func GuardExec(db *sql.DB, sessionID string) error {
	if db == nil {
		return fmt.Errorf("session guard requires a database handle")
	}
	var status, containerID, leaseID string
	err := db.QueryRow(`SELECT status, COALESCE(container_id, ''), lease_id FROM sessions WHERE id = ?`, sessionID).
		Scan(&status, &containerID, &leaseID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%q: %w", sessionID, ErrSessionNotFound)
		}
		return err
	}
	if status != "running" || containerID == "" {
		return fmt.Errorf("%q: %w", sessionID, ErrSessionNotRunning)
	}
	var leaseStatus string
	if err := db.QueryRow(`SELECT status FROM leases WHERE id = ?`, leaseID).Scan(&leaseStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%q: %w", sessionID, ErrLeaseInactive)
		}
		return err
	}
	if !activeLeaseStatuses[leaseStatus] {
		return fmt.Errorf("%q: %w (lease status %q)", sessionID, ErrLeaseInactive, leaseStatus)
	}
	return nil
}
