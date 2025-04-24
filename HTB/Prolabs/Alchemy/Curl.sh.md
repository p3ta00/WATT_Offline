```rust
#!/bin/bash

# Check if the input file and path are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <file_with_ip_list> <path>"
    exit 1
fi

# File containing the list of IPs
ip_file="$1"

# Path to curl
path="$2"

# Output file for curl results
output_file="curl_titles.txt"

# Clear the output file
> $output_file

# Loop through each IP address in the file
while IFS= read -r ip; do
    url="http://$ip$path"
    echo "[+] Curling $url..."
    title=$(curl -s "$url" | grep -oP '(?<=<title>)(.*)(?=</title>)' | sed 's/^ *//;s/ *$//')
    echo -e "$url - Title: $title" | tee -a $output_file
done < "$ip_file"

echo "Curl complete. Results saved to $output_file."
```

`curl_titles.sh` is a Bash script that reads a list of IP addresses from a file, performs a `curl` request to a specified path for each IP address, and extracts the title from the HTML response. The extracted titles are saved to an output file.

## Usage

sh

Copy code

`./curl_titles.sh <file_with_ip_list> <path>`

### Parameters

- `<file_with_ip_list>`: A file containing a list of IP addresses, one per line.
- `<path>`: The path to append to each IP address for the `curl` request.

### Example

sh

Copy code

`./curl_titles.sh 80.txt /panel/dashboard`

This example will read IP addresses from `80.txt` and perform a `curl` request to `http://<ip>/panel/dashboard` for each IP. It will extract the title from the HTML response and save the results to `curl_titles.txt`.

## Output

The script will create or overwrite a file named `curl_titles.txt` in the current directory. This file will contain the URLs and the extracted titles from the HTML responses.

