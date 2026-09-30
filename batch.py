from pathlib import Path # Import Path class from pathlib module to handle file paths
from analyser.parser import read_email # Import read_email function from analyser.parser module to parse email files
# Batch process email files
folder = Path("samples")

passed = 0 # Count of successfully parsed emails
failed = 0 # Count of failed parsing attempts

for path in sorted(folder.rglob("*.eml")): # Iterate through all .eml files in the folder and its subfolders (fake/, real/)
    try:
        parsed = read_email(path)
        print(f"PASSED: {path.name} : {parsed['subject']}") # Print the subject of the successfully parsed email
        passed += 1
    except Exception as error:
        print(f"FAILED: {path.name} : {error}") # Print the error message for failed parsing
        failed += 1
# Print summary
print(f"\n{passed} parsed, {failed} failed")