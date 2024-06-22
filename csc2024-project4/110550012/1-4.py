import zipfile
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

zip_file = os.path.join(script_dir, 'Matryoshka dolls.jpg')

destination_dir = script_dir

with zipfile.ZipFile(zip_file, 'r') as zip_ref:
    zip_ref.extractall(destination_dir)

old_file = os.path.join(destination_dir, 'flag.txt')
new_file = os.path.join(destination_dir, 'flag.png')

if os.path.exists(old_file):
    os.rename(old_file, new_file)
else:
    print(f"Error: The file {old_file} does not exist.")
