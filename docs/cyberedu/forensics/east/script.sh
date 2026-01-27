while IFS= read -r password; do
    [[ -z "$password" ]] && continue
    echo -ne "\rTrying: $password                    "
    if echo "$password" | 7z x -p"$password" hidden.7z -y >/dev/null 2>&1; then
        echo -e "\nSUCCESS: Password is '$password'"
        7z x -p"$password" hidden.7z
        break
    fi
done < <your path to rockyou.txt>