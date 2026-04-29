// Command db-inspect dumps the interchange's envelopes + pairs tables
// for debugging. Operator/diagnostic only — never wired into a server.
package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "./interchange.db", "sqlite path")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	fmt.Println("=== envelopes ===")
	rows, err := db.Query("SELECT msg_id, path_id, direction, ciphertext, signature, outer_json FROM envelopes ORDER BY msg_id")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for rows.Next() {
		var msgID, pathID, dir, ct, sig, outer string
		_ = rows.Scan(&msgID, &pathID, &dir, &ct, &sig, &outer)
		ctBytes, e1 := base64.RawURLEncoding.DecodeString(ct)
		if e1 != nil {
			ctBytes, _ = base64.StdEncoding.DecodeString(ct)
		}
		fmt.Printf("\nmsg_id  : %s\npath_id : %s\ndir     : %s\nct len  : %d\nct hex  : %s\nsig     : %s\nouter   :\n",
			msgID, pathID, dir, len(ctBytes), hex.EncodeToString(ctBytes), sig)
		var v any
		_ = json.Unmarshal([]byte(outer), &v)
		o, _ := json.MarshalIndent(v, "  ", "  ")
		fmt.Println(string(o))
	}
	rows.Close()

	fmt.Println("\n=== pairs ===")
	prows, err := db.Query("SELECT path_id, requester_id, requester_pubkey, requester_dh_pubkey, owner_id, owner_pubkey, owner_dh_pubkey, sig_alg, dh_alg FROM pairs")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for prows.Next() {
		var pathID, rid, rpk, rdpk, oid, opk, odpk, sigAlg, dhAlg string
		_ = prows.Scan(&pathID, &rid, &rpk, &rdpk, &oid, &opk, &odpk, &sigAlg, &dhAlg)
		fmt.Printf("\npath_id            : %s\nrequester          : %s\nrequester_pubkey   : %s\nrequester_dh_pubkey: %s\nowner              : %s\nowner_pubkey       : %s\nowner_dh_pubkey    : %s\nsig_alg            : %s\ndh_alg             : %s\n",
			pathID, rid, rpk, rdpk, oid, opk, odpk, sigAlg, dhAlg)
	}
	prows.Close()
}
