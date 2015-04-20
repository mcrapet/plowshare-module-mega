# Plowshare mega.co.nz module
# Copyright (c) 2013-2014 Plowshare team
#
# This file is part of Plowshare.
#
# Plowshare is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Plowshare is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Plowshare.  If not, see <http://www.gnu.org/licenses/>.
#
# Note: This module requires: hexdump, dd, base64, exec/mega executable

MODULE_MEGA_REGEXP_URL='https\?://\(www\.\)\?mega\.co\.nz/'

MODULE_MEGA_DOWNLOAD_OPTIONS="
IGNORE_CRC,,ignore-crc,,Ignore meta-MAC mismatch (in order to get file anyway)
HACK,,hack,,Use 'n' instead of 'p' in api request"
MODULE_MEGA_DOWNLOAD_RESUME=no
MODULE_MEGA_DOWNLOAD_FINAL_LINK_NEEDS_COOKIE=no
MODULE_MEGA_DOWNLOAD_SUCCESSIVE_INTERVAL=

MODULE_MEGA_UPLOAD_OPTIONS="
AUTH,a,auth,a=EMAIL:PASSWORD,User account
FOLDER,,folder,s=FOLDER,Folder to upload files into (account only)
NOSSL,,nossl,,Use HTTP upload url instead of HTTPS
PRIVATE_FILE,,private,,Do not allow others to download the file (account only)
EUROPE,,eu,,Use eu.api.mega.co.nz servers instead of g.api.mega.co.nz"
MODULE_MEGA_UPLOAD_REMOTE_SUPPORT=no

MODULE_MEGA_PROBE_OPTIONS="
HACK,,hack,,Use 'n' instead of 'p' in api request"

# Globals
# Note: Be sure to not increment MEGA_SEQ_NO in a subshell but outside.
declare -i MEGA_SEQ_NO=$(random d 10)
declare -r MEGA_CRYPTO=$(PATH="$PLOWSHARE_CONFDIR/exec:$LIBDIR/exec:$PATH" type -P mega 2>/dev/null)

# $1: hex buffer
# stdout: base64 buffer (MEGA variant)
hex_to_base64() {
    local IN=$(sed -e 's/../\\x&/g' <<<"$1")
    base64 -w 0 < <(echo -ne "$IN") | sed -e 'y=+/=-_=; s/=*$//'
}

# $1: base64 buffer (MEGA variant)
# stdout: hex buffer
base64_to_hex() {
    local IN=${1//_/\/}

    case $(( (${#IN} * 3) % 4 )) in
       2|3)
           IN="${IN}=="
           ;;
       1)
           IN="${IN}="
           ;;
    esac
    base64 -d < <(echo -n "${IN//-/+}") | hexdump -v -e '1/1 "%02X"'
}

# Ascii to hexstring + padding (add 1, 2 or 3 null bytes)
# $1: input (printable characters) string
# stdout: hexstring (length is multiple of 8)
hexstring() {
    local -r S=$1
    local I C REM

    for (( I = 0; I < ${#S}; I++ )); do
        C=${S:$I:1}
        LC_CTYPE=C printf "%X" "'$C"
    done

    REM=$(( ${#S} % 4 ))
    if (( REM > 0 )); then
        for (( I = $REM; I < 4; I++ )); do
            printf '00'
        done
    fi
}

# Perform a logical XOR operation of hexstring arguments
# $1: first hexstring
# $2: second hexstring
# Arguments can have different sizes
# stdout: xor'd hexstring
hex_xor() {
    local S1 S2 DIV REM

    if [ "${#1}" -gt "${#2}" ]; then
        S1=$1
        S2=$2
    else
        S1=$2
        S2=$1
    fi

    REM=$(( ${#S2} % 8 ))
    DIV=$(( ${#S2} / 8 ))

    for (( I = 0; I < DIV*8; I=I+8 )); do
        printf %08X $(( 16#${S1:$I:8} ^ 16#${S2:$I:8} ))
    done

    if [ "$REM" -gt 0 ]; then
        I=$((DIV * 8))
        printf %08X $(( 16#${S1:$I:$REM} ^ 16#${S2:$I:$REM} ))
    fi

    if [ "${#S1}" -gt "${#S2}" ]; then
        REM=$(( ${#S1} - ${#S2} ))
        I=${#S2}
        echo -ne "${S1:$I:$REM}"
    fi
}

# Parse MPI sequence
# $1: hexstring
# $2: how many number to process
mpi_parse() {
  local H=$1
  local -i OFFSET=0
  local -i N LEN

  for I in $2; do
      LEN=0

      # Read 16-bit prefix (gives the number of significant bits)
      for (( J = OFFSET; J < OFFSET + 4; J++ )); do
          (( LEN = 16 * LEN + 16#${H:$J:1} ))
      done

      N=$(( 2 * ((LEN + 7) / 8) ))
      OFFSET=$((OFFSET + 4))
      echo "${H:$OFFSET:$N}"
      OFFSET=$((OFFSET + N))
  done
}

# Decide upload chunck sizes
# According to official documentation: "Chunks can be sent in any order and
# can be of any size, [...]"
# website: upload_9.js, initupload3
# $1: positive integer number
# stdout: offset ':' chunk size (one pair per line)
get_chunks() {
    local -ir SZ=$1
    local -i P=0
    local -i I=1
    local -i PN=131072

    while [ "$PN" -le "$SZ" -a "$I" -lt 8 ]; do
        echo $P:$((I * 131072))
        (( ++I ))
        P=$PN
        PN=$((I * 131072 + PN))
    done

    while [ "$PN" -le "$SZ" ]; do
        echo $P:1048576
        P=$PN
        PN=$((PN + 1048576))
    done

    I=$((SZ - P))
    [ "$I" -gt 0 ] && echo "$P:$I"
}

# Compute CBC-MAC of a file
# $1: file (any filesize)
# $2: iv (hexstring)
# $3: key (hexstring)
# stdout: 128-bit hexstring
aes_cbc_mac() {
    $MEGA_CRYPTO mac "$1" "$3" "$2"
}

# $1: 128-bit key (hexstring)
# $2: plaintext 16 bytes block(s) (hexstring)
aes_cbc_encrypt() {
    $MEGA_CRYPTO cbc_enc "$1" "$2"
}

# $1: 128-bit key (hexstring)
# $2: ciphered 16 bytes block(s) (hexstring)
aes_cbc_decrypt() {
    $MEGA_CRYPTO cbc_dec "$1" "$2"
}

# $1: input file (plaintext data)
# $2: output file (ciphered data)
# $3: iv (hexstring).
# $4: 128-bit key (hexstring)
# stdout: updated iv (counter)
aes_ctr_encrypt() {
    $MEGA_CRYPTO ctr_enc "$1" "$2" "$4" "$3"
}

# $1: 128-bit key (hexstring format)
# $2: ciphered buffer (hexstring format)
mega_decrypt_key() {
    $MEGA_CRYPTO ecb_dec "$1" "$2"
}

# $1: 128-bit key (hexstring format)
# $2: plaintext buffer (hexstring format)
mega_encrypt_key() {
    $MEGA_CRYPTO ecb_enc "$1" "$2"
}

# $1: attribute(s) (JSON format)
# $2: AES key (4*8 hexdigits = 128-bit)
# stdout: hexstring (length is multiple of 32)
mega_enc_attr() {
    local ATTR=$(hexstring "MEGA$1")
    local REM=$(( ${#ATTR} % 32 ))

    if [ "$REM" -gt 0 ]; then
        local -r PADDING='00000000000000000000000000000000'
        ATTR="$ATTR${PADDING:$REM}"
    fi

    aes_cbc_encrypt "$2" "$ATTR"
}

# $1: ciphered attribute(s) (hexstring format)
# $2: AES key (4*8 hexdigits = 128-bit)
# stdout: hexstring (length is multiple of 32)
mega_dec_attr() {
    local ENC_ATTR=$1
    local KEY=$2
    local B C

    B=$(aes_cbc_decrypt "$KEY" "$ENC_ATTR" | sed -e 's/../\\x&/g')
    C=$(echo -ne "$B")

    if [ "${C:0:5}" != 'MEGA{' ]; then
        log_error "$FUNCNAME: error decoding"
        return $ERR_FATAL
    fi

    echo "${C:4}"
}

# Static function. Translate error status
mega_error() {
    local E=$((-$1))
    local -ar ERRORS=(
    "unknown ($1)"
    # General errors
    'EINTERNAL (-1): An internal error has occurred. Please submit a bug report, detailing the exact circumstances in which this error occurred'
    'EARGS (-2): You have passed invalid arguments to this command'
    'EAGAIN (-3) (always at the request level): A temporary congestion or server malfunction prevented your request from being processed. No data was altered. Retry. Retries must be spaced with exponential backoff'
    'ERATELIMIT (-4): You have exceeded your command weight per time quota. Please wait a few seconds, then try again (this should never happen in sane real-life applications)'
    # Upload errors
    'EFAILED (-5): The upload failed. Please restart it from scratch'
    'ETOOMANY (-6): Too many concurrent IP addresses are accessing this upload target URL'
    'ERANGE (-7): The upload file packet is out of range or not starting and ending on a chunk boundary'
    'EEXPIRED (-8): The upload target URL you are trying to access has expired. Please request a fresh one'
    # Filesystem/Account-level errors
    'ENOENT (-9): Object (typically, node or user) not found'
    'ECIRCULAR (-10): Circular linkage attempted'
    'EACCESS (-11): Access violation (e.g., trying to write to a read-only share)'
    'EEXIST (-12): Trying to create an object that already exists'
    'EINCOMPLETE (-13): Trying to access an incomplete resource'
    'EKEY (-14): A decryption operation failed (never returned by the API)'
    'ESID (-15): Invalid or expired user session, please relogin'
    'EBLOCKED (-16): User blocked'
    'EOVERQUOTA (-17): Request over quota'
    'ETEMPUNAVAIL (-18): Resource temporarily not available, please try again later'
    'ETOOMANYCONNECTIONS (-19): Too many connections on this resource'
    'EWRITE (-20): Write failed'
    'EREAD (-21): Read failed'
    'EAPPKEY (-22): Invalid application key; request not processed'
    )

    (( $E < 0 && $E > ${#ERRORS[@]} )) && E=0
    log_error "Remote error: ${ERRORS[$E]}"
}

# HTTP (POST) request (client => server)
# Note: Variables $MEGA_SESSION_ID and $MEGA_SEQ_NO are accessed directly.
# $1: data to send
# $2: (optional) node id
mega_api_req() {
    local -r DATA=$1
    local JSON API_URL

    if [ -z "$EUROPE" ]; then
        API_URL='https://eu.api.mega.co.nz'
    else
        API_URL='https://g.api.mega.co.nz'
    fi

    # Plowshare official application key
    local -r APP_KEY='08F3BSqb'

    log_debug "$FUNCNAME: '$DATA'"

    if [ -z "$MEGA_SESSION_ID" ]; then
        API_URL="$API_URL/cs?id=$MEGA_SEQ_NO&ak=$APP_KEY"
    else
        API_URL="$API_URL/cs?id=$MEGA_SEQ_NO&ak=$APP_KEY&sid=$MEGA_SESSION_ID"
    fi

    [ -z "$2" ] || API_URL="$API_URL&n=$2"

    JSON=$(curl -X POST --retry 2 --data-binary "[$DATA]" \
        -H 'Content-Type: text/plain; charset=UTF-8' \
        -H 'Origin: Plowshare' "$API_URL") || return
    JSON=${JSON#[}
    JSON=${JSON%]}

    if [ ${#JSON} -le 3 ]; then
        [ "$JSON" != '-9' ] || return $ERR_LINK_DEAD
        mega_error "$JSON"
        [ "$JSON" != '-3' ] || return $ERR_NETWORK
        return $ERR_FATAL
    fi

    echo "$JSON"
}

# Static function. Find RootId (Root Cloud Drive)
mega_get_rootid() {
    local JSON

    # command "f": Fetch node tree
    JSON=$(mega_api_req '{"a":"f","c":1}') || return

    # t=2: root node ("Cloud Drive")
    # FIXME. Crude parsing.
    echo "${JSON%%\"t\":2*}" | parse_json 'h'
    echo
}

# Static function. Find FolderId
# $1: 128-bit key (hexstring format)
# $2: (leaf) folder name. No hierarchy ('/' character is valid for a folder name)
# stdout (2 lines): folder handle + shared master key (empty for local folders)
mega_get_folderid() {
    local -r AESKEY=$1
    local -r NAME=$2
    local JSON LINE ENC_ATTR ATTR ENC_KEY KEY FOLDER_NAME ENC_SHKEY SHKEY
    local -a ENC_KEYS

    # command "f": Fetch node tree
    # TODO: see extra paramters: "r":1
    JSON=$(mega_api_req '{"a":"f","c":1}' | \
        sed -e 's/}[[:space:]]*[],]/}\n/g' | \
        sed -ne '/"t"[[:space:]]*:[[:space:]]*1/p') || return

    # Grep all directories (one per line).
    # t: filetype (1 for directory)
    # p: parent handle
    # sk: shared key
    # su: shared user
    # {"h":"FsU3gQCA","p":"YsVBWSzJ","u":"lPymiGWTSiA","t":1,"a":"gd-f0USMKuaPUwcSoqtRXg","k":"lPymiGWTSiA:70ey9v0w0M1cI-Kt1wR98A","ts":1374527356}
    # {"h":"Ox5WTJ5Q","p":"bk4C1ToD","u":"kz5HBLnEkOM","t":1,"a":"gzz_qwO8ZK9noa6JjpBQIj3PAA4V_VQGEoGtMdraqe4","k":"Ox5WTJ5Q:dJ6oqJEdy6l2fuaoCyq7zQ","r":0,"su":"kz5HBLnEkOM","sk":"kT6_Z94WD7hnc---ISZNHw","ts":1375614490}
    for LINE in $JSON; do
        ENC_ATTR=$(parse_json a <<< "$LINE") || return
        ENC_KEY=$(parse_json k <<< "$LINE") || return

        IFS=':/' read -r -a ENC_KEYS <<<"$ENC_KEY"
        ENC_KEY=${ENC_KEYS[1]}
        ENC_KEY=$(base64_to_hex "$ENC_KEY")

        ENC_SHKEY=$(parse_json_quiet sk <<< "$LINE")
        if [ -n "$ENC_SHKEY" ]; then
            ENC_SHKEY=$(base64_to_hex "$ENC_SHKEY")
            SHKEY=$(mega_decrypt_key "$AESKEY" "$ENC_SHKEY")
            KEY=$(mega_decrypt_key "$SHKEY" "$ENC_KEY")
        else
            SHKEY=''
            KEY=$(mega_decrypt_key "$AESKEY" "$ENC_KEY")
        fi

        ENC_ATTR=$(base64_to_hex "$ENC_ATTR")
        ATTR=$(mega_dec_attr "$ENC_ATTR" "$KEY") || return
        FOLDER_NAME=$(echo "$ATTR" | parse_json n) || return

        if [ "$FOLDER_NAME" = "$NAME" ]; then
            local H R
            H=$(parse_json h <<< "$LINE") || return
            log_debug "found '$NAME', h:'$H'"

            # Check permissions. If accesslevel is present:
            # readonly: r=0 ; readwrite: r=1 ; fullaccess: r=2; owner: r=4
            R=$(parse_json_quiet r <<< "$LINE")
            if [[ "$R" = '0' ]]; then
                log_error 'Shared folder seems to be read only. Aborting.'
                return $ERR_LINK_NEED_PERMISSIONS
            fi

            echo "$H"
            echo "$SHKEY"
            return 0
        fi

        #log_error "available folder: '$FOLDER_NAME'"
    done

    log_error "No folder named '$NAME' has been found. Aborting."
    return $ERR_BAD_COMMAND_LINE
}

# Static function.
# $1: password string
mega_prepare_key() {
    local KEY=$1
    local REM

    if [ "${#KEY}" -gt 16 ]; then
        log_error 'Your password is >16 characters, it is not supported actually.'
        log_error 'This would requires some more crypo (65536 openssl calls). Too slow for now..'
        return $ERR_FATAL
    fi

    KEY=$(hexstring "$1")

    REM=$(( ${#KEY} % 32 ))
    if [ "$REM" -gt 0 ]; then
        local -r PADDING='00000000000000000000000000000000'
        KEY="$KEY${PADDING:$REM}"
    fi

    $MEGA_CRYPTO mac0 1048576 "$KEY" '93C467E37DB0C7A4D1BE3F810152CB56' || return
}

# Static function
# $1: email string
# $2: AES key (4*8 hexdigits = 128-bit)
mega_stringhash() {
    local HEX=$(hexstring "$(lowercase "$1")")
    local -r KEY=$2

    local I REM ENC
    local RES='00000000000000000000000000000000'

    REM=$(( ${#HEX} % 32 ))
    [ "$REM" -gt 0 ] && HEX="$HEX${RES:$REM}"

    for (( I = 0; I < ${#HEX}; I=I+32)); do
        RES=$(hex_xor "$RES" "${HEX:$I:32}")
    done

    ENC=$($MEGA_CRYPTO mac0 262144 "$KEY" "$RES") || return

    # Take 1st & 3rd DWORD
    hex_to_base64 "${ENC:0:8}${ENC:16:8}"
}

mega_login() {
    local -r AUTH=$1
    local EMAIL PASSWORD AESKEY HASH JSON K PRIVK CSID
    local ENC_MASTER_KEY MASTER_KEY ENC_RSA_PRIV_KEY RSA_PRIV_KEY
    local RSA_P RSA_Q RSA_D RSA_QINV ENC_CSID_N CSID_N

    split_auth "$AUTH" EMAIL PASSWORD || return

    AESKEY=$(mega_prepare_key "$PASSWORD") || return $ERR_LOGIN_FAILED
    HASH=$(mega_stringhash "$EMAIL" "$AESKEY") || return $ERR_LOGIN_FAILED

    # command "us": Login session challenge/response
    # uh: AES stringhash (of login+password)
    JSON=$(mega_api_req '{"a":"us","user":"'"$EMAIL"'","uh":"'"$HASH"'"}') || \
        return $ERR_LOGIN_FAILED

    # k: master key (encrypted with $AESKEY)
    # privk: RSA private key (encrypted with master key)
    # csid: the session ID (encrypted with RSA private key)
    K=$(echo "$JSON" | parse_json k) || return
    PRIVK=$(echo "$JSON" | parse_json privk) || return
    CSID=$(echo "$JSON" | parse_json csid) || return

    ENC_MASTER_KEY=$(base64_to_hex "$K")
    MASTER_KEY=$(mega_decrypt_key "$AESKEY" "$ENC_MASTER_KEY")
    ENC_RSA_PRIV_KEY=$(base64_to_hex "$PRIVK")
    RSA_PRIV_KEY=$(mega_decrypt_key "$MASTER_KEY" "$ENC_RSA_PRIV_KEY")

    # This RSA Private key contains 4 Multi-precision integers (MPI)
    # p: The first factor of n (prime1)
    # q: The second factor of n (prime2)
    # d: The private exponent (privateExponent)
    # u: The CRT coefficient (coefficient). qInv = (1/p) mod q [where q>p]
    { read RSA_P; read RSA_Q; read RSA_D; read RSA_QINV; } < <(mpi_parse "$RSA_PRIV_KEY" '1 2 3 4')

    read ENC_CSID_N < <(mpi_parse $(base64_to_hex "$CSID") 1)

    log_debug 'uncrpyt session ID with RSA Private Key'

    CSID_N=$($MEGA_CRYPTO rsa "$RSA_P" "$RSA_Q" "$RSA_D" "$ENC_CSID_N") || {
        log_error 'rsa failure';
        return $ERR_FATAL;
    }

    (( ${#CSID_N} % 2 != 0 )) && CSID_N="0$CSID_N"

    # Session ID length is 43 bytes
    hex_to_base64 "${CSID_N:0:86}"
    echo
    echo "$MASTER_KEY"
}

#mega_anon_login() {
#    local AESKEY JSON MASTER_KEY SESSION_SELF_CHALLENGE ENC_KEY ENC_SSC
#    local ENC_MASTER_KEY USER K TSID
#
#    # AES 128-bit key
#    AESKEY=$(mega_prepare_key "$(random ll 16)")
#    MASTER_KEY=$(random H 32)
#    SESSION_SELF_CHALLENGE=$(random H 32)
#
#    ENC_KEY=$(mega_encrypt_key "$MASTER_KEY" "$AESKEY")
#    ENC_SSC=$(mega_encrypt_key "$SESSION_SELF_CHALLENGE" "$MASTER_KEY")
#
#    JSON=$(mega_api_req '{"a":"up","k":"'"$(hex_to_base64 "$ENC_KEY")\
#"'","ts":"'"$(hex_to_base64 "$SESSION_SELF_CHALLENGE$ENC_SSC")"'"}') || \
#        return $ERR_LOGIN_FAILED
#
#    USER=${JSON#\"}
#    USER=${USER%\"}
#    log_debug "user handle: '$USER'"
#
#    if [ -z "$USER" ]; then
#        log_error 'unable to create ephemeral account'
#        return $ERR_LOGIN_FAILED
#    fi
#
#    JSON=$(mega_api_req '{"a":"us","user":"'"$USER"'"}') || \
#        return $ERR_LOGIN_FAILED
#
#    # k: master key (encrypted with $AESKEY)
#    # tsid: the session ID
#    K=$(echo "$JSON" | parse_json k) || return
#    TSID=$(echo "$JSON" | parse_json tsid) || return
#
#    ENC_MASTER_KEY=$(base64_to_hex "$K")
#
#    if [ "$ENC_MASTER_KEY" != "$ENC_KEY" ]; then
#        log_error 'master key mismatch!'
#        return $ERR_LOGIN_FAILED
#    fi
#
#    echo "$TSID"
#    echo "$MASTER_KEY"
#}

# Output an mega.co.nz file download URL
# $1: cookie file (unused here)
# $2: mega url
# stdout: real file download link ? (ciphered file..)
mega_download() {
    local -r URL=$2

    local FILE_ID FILE_KEY KEY C OFFSET LENGTH TMP_FILE
    local AES_IV4 AES_IV5 META_MAC AESKEY JSON
    local FILE_URL FILE_SIZE ENC_ATTR FILE_ATTR FILE_NAME
    local FILE_MAC CHUNK_MAC CHECK_MAC_HI CHECK_MAC_LO

    IFS="!" read -r _ FILE_ID FILE_KEY <<< "$URL"

    if [ -z "$FILE_ID" ]; then
        log_error 'file id is missing, bad link'
        return $ERR_FATAL
    fi

    if [ -z "$FILE_KEY" ]; then
        log_error 'file key is missing, bad link'
        return $ERR_FATAL
    fi

    if match '/#F!' "$URL"; then
        log_error 'This is a folder link, use plowlist'
        return $ERR_FATAL
    fi

    KEY=$(base64_to_hex "$FILE_KEY")
    AES_IV4=${KEY:32:8}
    AES_IV5=${KEY:40:8}

    # 64-bit meta-MAC
    META_MAC=${KEY:48:16}

    AESKEY=$(hex_xor "${KEY:0:32}" "${KEY:32:32}")

    if [ -z "$HACK" ]; then
        JSON=$(mega_api_req '{"a":"g","g":1,"p":"'"$FILE_ID"'"}') || return
    else
        JSON=$(mega_api_req '{"a":"g","g":1,"n":"'"$FILE_ID"'"}') || return
    fi
    (( ++MEGA_SEQ_NO ))

    FILE_URL=$(echo "$JSON" | parse_json g) || return
    FILE_SIZE=$(echo "$JSON" | parse_json s) || return
    ENC_ATTR=$(echo "$JSON" | parse_json at) || return
    ENC_ATTR=$(base64_to_hex "$ENC_ATTR")
    FILE_ATTR=$(mega_dec_attr "$ENC_ATTR" "$AESKEY") || return
    FILE_NAME=$(echo "$FILE_ATTR" | parse_json n) || return

    TMP_FILE=$(create_tempfile '.mega') || return

    # Note: We should not use curl_with_log, this the *final* url but
    # we need to decrypt file content.
    curl_with_log -o "$TMP_FILE" "$FILE_URL" || return

    # Decrypt "$TMP_FILE" with AES-CTR (with $AESKEY)
    COUNTER="${AES_IV4}${AES_IV5}0000000000000000"
    COUNTER=$(aes_ctr_encrypt "$TMP_FILE" "${TMP_FILE}.dec" "$COUNTER" "$AESKEY")

    local -a CHUNKS=($(get_chunks $FILE_SIZE))
    log_debug "number of chunks: ${#CHUNKS[@]}"

    for C in ${CHUNKS[@]}; do
        IFS=':' read -r OFFSET LENGTH <<<"$C"

        if (( LENGTH % 131072 == 0 )); then
            log_debug "offset: $OFFSET, length: $LENGTH"
            (( LENGTH /= 131072 ))
            (( OFFSET /= 131072 ))
            dd if="${TMP_FILE}.dec" bs=131072 skip=$OFFSET count=$LENGTH of="$TMP_FILE" 2>/dev/null
        else
            log_debug "offset: $OFFSET, length: $LENGTH (last)"
            dd if="${TMP_FILE}.dec" bs=1 skip=$OFFSET count=$LENGTH of="$TMP_FILE" 2>/dev/null
        fi

        # CBC-MAC of this chunk
        CHUNK_MAC=$(aes_cbc_mac "$TMP_FILE" "$AES_IV4$AES_IV5$AES_IV4$AES_IV5" "$AESKEY")
        FILE_MAC="$FILE_MAC$CHUNK_MAC"
    done

    rm -f "$TMP_FILE"

    # CBC-MAC to get File MAC
    C=$(sed -e 's/../\\x&/g' <<<"$FILE_MAC")
    echo -ne "$C" >"$TMP_FILE"
    FILE_MAC=$(aes_cbc_mac "$TMP_FILE" '00000000000000000000000000000000' "$AESKEY")
    log_debug "file-MAC: $FILE_MAC"

    CHECK_MAC_HI=$(hex_xor "${FILE_MAC:0:8}" "${FILE_MAC:8:8}")
    CHECK_MAC_LO=$(hex_xor "${FILE_MAC:16:8}" "${FILE_MAC:24:8}")

    log_debug "meta-MAC: $CHECK_MAC_HI$CHECK_MAC_LO"
    if [ "$META_MAC" = "$CHECK_MAC_HI$CHECK_MAC_LO" ]; then
        log_debug 'meta mac correct'

        echo "file://${TMP_FILE}.dec"
        echo "$FILE_NAME"
        return 0
    fi

    log_error "meta-MAC mismatch! $META_MAC expected"

    if [ -n "$IGNORE_CRC" ]; then
        echo "file://${TMP_FILE}.dec"
        echo "$FILE_NAME"
        return 0
    fi

    return $ERR_FATAL
}

# Upload a file to mega.co.nz
# $1: cookie file (unused here)
# $2: input file (with full path)
# $3: remote filename
# stdout: mega download link
mega_upload() {
    local -r FILE=$2
    local -r DESTFILE=$3

    local SZ TMP_FILE JSON UP_URL C OFFSET LENGTH FOLDER_ID
    local AESKEY AES_IV4 AES_IV5 TOKEN FILE_MAC CHUNK_MAC
    local META_MAC_HI META_MAC_LO KEY_1 KEY_2 KEY_3 KEY_4 NODE_KEY
    local FILE_ATTR ENC_KEY FILE_DATA FILE_ID SHARE_DATA
    local MEGA_SESSION_ID MEGA_MASTER_KEY MEGA_SHARED_KEY

    if [ ! -f "$MEGA_CRYPTO" ]; then
        log_error "External mega executable not found: $MEGA_CRYPTO"
        return $ERR_SYSTEM
    fi

    # Sanity check
    [ -n "$AUTH" ] || return $ERR_LINK_NEED_PERMISSIONS

    C=$(mega_login "$AUTH") || return
    { read MEGA_SESSION_ID; read MEGA_MASTER_KEY; } <<< "$C"
    (( ++MEGA_SEQ_NO ))

    log_debug "session ID: '$MEGA_SESSION_ID'"

    if [ -n "$AUTH" -a -n "$FOLDER" ]; then
        C=$(mega_get_folderid "$MEGA_MASTER_KEY" "$FOLDER") || return
    else
        C=$(mega_get_rootid) || return
    fi
    (( ++MEGA_SEQ_NO ))
    { read FOLDER_ID; read MEGA_SHARED_KEY; } <<< "$C"

    SZ=$(get_filesize "$FILE") || return

    # command "u": Request upload target URL
    # TODO: see extra paramters: "ms":0, "r":0, "e":0
    if [ -z "$NOSSL" ]; then
        JSON=$(mega_api_req '{"a":"u","ssl":1,"s":'$SZ'}') || return
    else
        JSON=$(mega_api_req '{"a":"u","s":'$SZ'}') || return
    fi
    (( ++MEGA_SEQ_NO ))

    UP_URL=$(echo "$JSON" | parse_json p) || return
    log_debug "upload URL: '$UP_URL'"

    TMP_FILE=$(create_tempfile '.mega') || return

    # AES 128-bit key for new file
    AESKEY=$(random H 32)
    AES_IV4=$(random H 8)
    AES_IV5=$(random H 8)
    COUNTER="${AES_IV4}${AES_IV5}0000000000000000"

    FILE_MAC=""
    TOKEN=""

    local -a CHUNKS=($(get_chunks $SZ))
    local N I

    N=${#CHUNKS[@]}
    I=1

    for C in ${CHUNKS[@]}; do
        IFS=':' read -r OFFSET LENGTH <<<"$C"

        log_error "chunk $I/$N: offset: $OFFSET, length: $LENGTH"
        if (( LENGTH % 131072 == 0 )); then
            dd if="$2" bs=131072 skip=$((OFFSET/131072)) \
                count=$((LENGTH/131072)) of="$TMP_FILE" 2>/dev/null
        else
            dd if="$2" bs=1 skip=$OFFSET count=$LENGTH of="$TMP_FILE" 2>/dev/null
        fi

        # CBC-MAC of this chunk
        CHUNK_MAC=$(aes_cbc_mac "$TMP_FILE" "$AES_IV4$AES_IV5$AES_IV4$AES_IV5" "$AESKEY")
        FILE_MAC="$FILE_MAC$CHUNK_MAC"

        # AES-CTR mode does not require plaintext padding
        COUNTER=$(aes_ctr_encrypt "$TMP_FILE" "${TMP_FILE}.enc" "$COUNTER" "$AESKEY")

        # 2 tries
        TOKEN=$(curl -X POST --data-binary "@${TMP_FILE}.enc" \
                -H 'Origin: Plowshare' "$UP_URL/$OFFSET") || {
            wait 5 || return
            log_error "chunk $I/$N: retry";
            TOKEN=$(curl -X POST --data-binary "@${TMP_FILE}.enc" \
                    -H 'Origin: Plowshare' "$UP_URL/$OFFSET") || return
        }

        # Empty result is not an error.
        if [ -n "$TOKEN" ]; then
            log_debug "upload token: '$TOKEN'"
            if [ "${#TOKEN}" -le 3 ]; then
                log_error "Upload chunck error! offset=$OFFSET"
                mega_error "$TOKEN"
                return $ERR_FATAL
            fi
        fi

        (( ++I ))
    done

    # CBC-MAC to get File MAC
    C=$(sed -e 's/../\\x&/g' <<<"$FILE_MAC")
    echo -ne "$C" >"$TMP_FILE"
    FILE_MAC=$(aes_cbc_mac "$TMP_FILE" '00000000000000000000000000000000' "$AESKEY")
    log_debug "upload file mac: $FILE_MAC"

    rm "$TMP_FILE" "${TMP_FILE}.enc"

    if [ -z "$TOKEN" ]; then
        log_error 'Empty upload token (completion handle)'
        # Cancel upload ?
        #mega_api_req '{"a":"u","t":"'"$UP_URL"'"}'
        return $ERR_FATAL
    fi

    META_MAC_HI=$(hex_xor "${FILE_MAC:0:8}" "${FILE_MAC:8:8}")
    META_MAC_LO=$(hex_xor "${FILE_MAC:16:8}" "${FILE_MAC:24:8}")
    KEY_1=$(hex_xor "${AESKEY:0:8}" "${AES_IV4}")
    KEY_2=$(hex_xor "${AESKEY:8:8}" "${AES_IV5}")
    KEY_3=$(hex_xor "${AESKEY:16:8}" "${META_MAC_HI}")
    KEY_4=$(hex_xor "${AESKEY:24:8}" "${META_MAC_LO}")

    NODE_KEY="$KEY_1$KEY_2$KEY_3$KEY_4$AES_IV4$AES_IV5$META_MAC_HI$META_MAC_LO"
    log_debug "upload node key: $NODE_KEY"

    FILE_ATTR=$(mega_enc_attr '{"n":"'"$DESTFILE"'"}' "$AESKEY")

    # h: new node; ph: new public node
    # t=0: regular file node
    ENC_KEY=$(mega_encrypt_key "$MEGA_MASTER_KEY" "$NODE_KEY")
    FILE_DATA="{\"h\":\"$TOKEN\",\"t\":0,\"a\":\"\
$(hex_to_base64 "$FILE_ATTR")\",\"k\":\"$(hex_to_base64 "$ENC_KEY")\"}"

    if [ -z "$MEGA_SHARED_KEY" ]; then
        # command "p": Put nodes
        # t : id of target parent node (directory)
        JSON=$(mega_api_req '{"a":"p","t":"'"$FOLDER_ID"'","n":['"$FILE_DATA"']}') || return
        (( ++MEGA_SEQ_NO ))

        FILE_ID=$(parse_json h <<< "$JSON")
        log_debug "file id (private): '$FILE_ID'"

        if [ -z "$PRIVATE_FILE" ]; then
            # command "l": Set public handle
            FILE_ID=$(mega_api_req '{"a":"l","n":"'"$FILE_ID"'"}') || return
            (( ++MEGA_SEQ_NO ))

            FILE_ID=${FILE_ID#\"}
            FILE_ID=${FILE_ID%\"}
            log_debug "file id (public): '$FILE_ID'"
        fi
    else
        ENC_KEY=$(mega_encrypt_key "$MEGA_SHARED_KEY" "$NODE_KEY")
        SHARE_DATA="[\"$FOLDER_ID\"],[\"$TOKEN\"],[0,0,\"$(hex_to_base64 "$ENC_KEY")\"]"

        # command "p": Put nodes
        # t : id of target parent node (directory)
        JSON=$(mega_api_req '{"a":"p","t":"'"$FOLDER_ID"'","n":['"$FILE_DATA"'],"cr":['"$SHARE_DATA"']}') || return
        (( ++MEGA_SEQ_NO ))

        FILE_ID=$(parse_json h <<< "$JSON")
        log_debug "file id (in shared folder): '$FILE_ID'"
    fi

    echo 'https://mega.co.nz/#!'"$FILE_ID"'!'"$(hex_to_base64 $NODE_KEY)"
}

# List a mega shareed folder
# $1: folder link URL
# $2: recurse subfolders (null string means not selected)
# stdout: list of links and file names (alternating)
mega_list() {
    local -r URL=$1
    local FOLDER_ID FOLDER_KEY JSON KEY AESKEY FILE_ID
    local ENC_KEY NODE_KEY_FULL NODE_KEY ENC_ATTR FILE_ATTR FILE_NAME

    if ! match '/#F!' "$URL"; then
        log_error 'This is not a directory list'
        return $ERR_FATAL
    fi

    IFS="!" read -r _ FOLDER_ID FOLDER_KEY <<< "$URL"

    if [ -z "$FOLDER_ID" ]; then
        log_error 'folder id is missing, bad link'
        return $ERR_FATAL
    fi

    if [ -z "$FOLDER_KEY" ]; then
        log_error 'folder key is missing, bad link'
        return $ERR_FATAL
    fi

    # command "f": Fetch node tree
    #JSON=$(mega_api_req '{"a":"f","c":1,"r":1}' "$FOLDER_ID" |
    JSON=$(mega_api_req '{"a":"f","c":1}' "$FOLDER_ID" | \
        sed -e 's/},{/},\n{/g' | \
        sed -ne '/"t"[[:space:]]*:[[:space:]]*0/p') || return
    (( ++MEGA_SEQ_NO ))

    KEY=$(base64_to_hex "$FOLDER_KEY")
    AESKEY=$(hex_xor "${KEY:0:32}" "${KEY:32:32}")

    # Grep all files (one per line).
    # t: filetype (0 for regular file)
    # {"h":"zR8niALR","p":"GJclVaKI","u":"65fYYu5ZLBU","t":0,"a":"p91p4G1aF4DSOUajkxGgTuJDBnGqXIa4XBNSkJu1zwkWjhS8iCZmdoCRWDX3ebmBDemU_VFYvoAGTq8mb6LtuQ","k":"GJclVaKI:vhe23fV90E6We7hrSzoXtZYafjBwjqYSQcAZOlrQGLo","s":2529042,"ts":1395678307}],"sn":"IDuVU07Ia4A"}
    while read -r ; do
        FILE_ID=$(parse_json h <<< "$REPLY") || continue

        ENC_KEY=$(parse_json k <<< "$REPLY") || continue
        ENC_KEY=$(base64_to_hex "${ENC_KEY#*:}")
        NODE_KEY_FULL=$(mega_decrypt_key "$AESKEY" "$ENC_KEY")
        NODE_KEY=$(hex_xor "${NODE_KEY_FULL:0:32}" "${NODE_KEY_FULL:32:32}")

        # {"n":"andalouvibe.opus","c":"NELir5yRjHQZW-FQx0RSEQSaP_1S"}
        ENC_ATTR=$(parse_json a <<< "$REPLY")
        ENC_ATTR=$(base64_to_hex "$ENC_ATTR")
        FILE_ATTR=$(mega_dec_attr "$ENC_ATTR" "$NODE_KEY") || return
        FILE_NAME=$(parse_json n <<< "$FILE_ATTR") || return

        echo 'https://mega.co.nz/#!'"$FILE_ID"'!'"$(hex_to_base64 $NODE_KEY_FULL)"
        echo "$FILE_NAME"
    done <<< "$JSON"
    log_error 'Warning: Concerning these links, you must use --hack command line switch when using with plowdown or plowprobe.'
}

# Probe a download URL
# $1: cookie file (unused here)
# $2: mega url
# $3: requested capability list
# stdout: 1 capability per line
mega_probe() {
    local -r URL=$2
    local REQ_IN=$3
    local JSON FILE_ID FILE_KEY REQ_OUT

    IFS="!" read -r _ FILE_ID FILE_KEY <<< "$URL"

    if [ -z "$FILE_ID" ]; then
        log_error 'File id is missing, bad link'
        return $ERR_FATAL
    fi

    if [ -z "$FILE_KEY" ]; then
        log_error 'File key is missing, decryption key is required to get filename'
        REQ_IN=${REQ_IN/f}
    fi

    # Note: Suitable status is returned for dead links
    if [ -z "$HACK" ]; then
        JSON=$(mega_api_req '{"a":"g","g":1,"p":"'"$FILE_ID"'"}') || return
    else
        JSON=$(mega_api_req '{"a":"g","g":1,"n":"'"$FILE_ID"'"}') || return
    fi
    (( ++MEGA_SEQ_NO ))

    REQ_OUT=c

    if [[ $REQ_IN = *f* ]]; then
        local KEY AESKEY ENC_ATTR

        KEY=$(base64_to_hex "$FILE_KEY")
        AESKEY=$(hex_xor "${KEY:0:32}" "${KEY:32:32}")
        ENC_ATTR=$(echo "$JSON" | parse_json at) || return
        ENC_ATTR=$(base64_to_hex "$ENC_ATTR")
        parse_json n < <(mega_dec_attr "$ENC_ATTR" "$AESKEY") && \
            REQ_OUT="${REQ_OUT}f"
    fi

    if [[ $REQ_IN = *s* ]]; then
        parse_json s <<< "$JSON" && REQ_OUT="${REQ_OUT}s"
    fi

    echo $REQ_OUT
}
