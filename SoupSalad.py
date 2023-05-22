import os
import threading
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
import itertools
import pickle
from datetime import datetime

root = tk.Tk()
root.title("Password List Generator")
root.geometry("350x350")
#root.resizable(False, False)  # Disable window resizing


entry_name = None
entry_surname = None
entry_city = None
entry_birthdate = None
entry_min_chars = None
entry_max_chars = None
entry_special_chars = None
progress_var = None
status_text = None
password_list = []
is_running = False

def generate_password_list(profile, output_file, min_length, max_length, special_chars):
    global progress_var, status_text, password_list, is_running

    # Extract profile information
    name = profile.get("name", "")
    surname = profile.get("surname", "")
    city = profile.get("city", "")
    birthdate = profile.get("birthdate", "")

    # Check if mandatory fields are provided
    if not name or not surname or not city:
        messagebox.showerror("Error", "Please fill in all the mandatory fields.")
        return

    # Open the file in write mode
    with open(output_file, "w", encoding="utf-8") as file:
        # Combine all letters and numbers from the input fields
        combined_input = name + surname + city + birthdate
        characters = ''.join(set(combined_input))

        # Add special characters
        if special_chars:
            characters += special_chars

        # Generate passwords within the length range
        for length in range(min_length, max_length + 1):
            combinations = itertools.product(characters, repeat=length)
            total_combinations = len(characters) ** length
            start_time = datetime.now()  # Track start time for calculating estimated time
            for i, combination in enumerate(combinations, 1):
                if not is_running:
                    return  # Pause the password generation process

                password = ''.join(combination)
                password_list.append(password)
                file.write(password + "\n")

                progress_var.set(i / total_combinations * 100)  # Update the progress bar variable
                elapsed_time = datetime.now() - start_time  # Calculate elapsed time
                elapsed_time_str = str(elapsed_time).split(".")[0]  # Format elapsed time
                estimated_time = elapsed_time / i * (total_combinations - i)  # Calculate estimated time
                estimated_time_str = str(estimated_time).split(".")[0]  # Format estimated time
                status_text.set(f"Generating password list... {progress_var.get():.2f}% complete\nElapsed time: {elapsed_time_str}\nEstimated time: {estimated_time_str}")
                root.update()  # Update the GUI window

def save_password_list():
    global is_running

    output_dir = filedialog.askdirectory()
    if output_dir:
        output_filename = f"Passwordlist-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        output_file = os.path.join(output_dir, output_filename)

        profile = {
            "name": entry_name.get(),
            "surname": entry_surname.get(),
            "city": entry_city.get(),
            "birthdate": entry_birthdate.get(),
        }
        min_length = int(entry_min_chars.get())
        max_length = int(entry_max_chars.get())
        special_chars = entry_special_chars.get()

        if is_running:
            is_running = False  # Pause the password generation process
            return

        is_running = True
        threading.Thread(target=generate_password_list, args=(profile, output_file, min_length, max_length, special_chars)).start()

def save_profile():
    profile_data = {
        "name": entry_name.get(),
        "surname": entry_surname.get(),
        "city": entry_city.get(),
        "birthdate": entry_birthdate.get(),
        "min_chars": entry_min_chars.get(),
        "max_chars": entry_max_chars.get(),
        "special_chars": entry_special_chars.get(),
    }

    file_path = filedialog.asksaveasfilename(defaultextension=".profile")
    if file_path:
        with open(file_path, "wb") as file:
            pickle.dump(profile_data, file)

def load_profile():
    file_path = filedialog.askopenfilename(filetypes=[("Profile Files", "*.pkl")])
    if file_path:
        with open(file_path, "rb") as file:
            profile_data = pickle.load(file)
            entry_name.delete(0, tk.END)
            entry_name.insert(tk.END, profile_data["name"])
            entry_surname.delete(0, tk.END)
            entry_surname.insert(tk.END, profile_data["surname"])
            entry_city.delete(0, tk.END)
            entry_city.insert(tk.END, profile_data["city"])
            entry_birthdate.delete(0, tk.END)
            entry_birthdate.insert(tk.END, profile_data["birthdate"])
            entry_min_chars.delete(0, tk.END)
            entry_min_chars.insert(tk.END, profile_data["min_chars"])
            entry_max_chars.delete(0, tk.END)
            entry_max_chars.insert(tk.END, profile_data["max_chars"])
            entry_special_chars.delete(0, tk.END)
            entry_special_chars.insert(tk.END, profile_data["special_chars"])

def generate_password_list_gui():
    global entry_name, entry_surname, entry_city, entry_birthdate, entry_min_chars, entry_max_chars, entry_special_chars, progress_var, status_text

    # Create input fields
    label_name = ttk.Label(root, text="Name:")
    label_name.grid(row=0, column=0, sticky="E")
    entry_name = ttk.Entry(root)
    entry_name.grid(row=0, column=1, padx=5)

    label_surname = ttk.Label(root, text="Surname:")
    label_surname.grid(row=1, column=0, sticky="E")
    entry_surname = ttk.Entry(root)
    entry_surname.grid(row=1, column=1, padx=5)

    label_city = ttk.Label(root, text="City:")
    label_city.grid(row=2, column=0, sticky="E")
    entry_city = ttk.Entry(root)
    entry_city.grid(row=2, column=1, padx=5)

    # Birthdate input field
    label_birthdate = ttk.Label(root, text="Birthdate (DDMMYYYY):")
    label_birthdate.grid(row=3, column=0, sticky="E")
    entry_birthdate = ttk.Entry(root)
    entry_birthdate.insert(tk.END, "1990")
    entry_birthdate.grid(row=3, column=1, padx=5)

    # Minimum characters input field
    label_min_chars = ttk.Label(root, text="Minimum Characters:")
    label_min_chars.grid(row=4, column=0, sticky="E")
    entry_min_chars = ttk.Entry(root)
    entry_min_chars.grid(row=4, column=1, padx=5)

    # Maximum characters input field
    label_max_chars = ttk.Label(root, text="Maximum Characters:")
    label_max_chars.grid(row=5, column=0, sticky="E")
    entry_max_chars = ttk.Entry(root)
    entry_max_chars.grid(row=5, column=1, padx=5)

    # Special characters input field
    label_special_chars = ttk.Label(root, text="Special Characters:")
    label_special_chars.grid(row=6, column=0, sticky="E")
    entry_special_chars = ttk.Entry(root)
    entry_special_chars.grid(row=6, column=1, padx=5)

    # Create save profile button
    save_profile_button = ttk.Button(root, text="Save Profile", command=save_profile)
    save_profile_button.grid(row=7, column=0, padx=5, pady=10)

    # Create load profile button
    load_profile_button = ttk.Button(root, text="Load Profile", command=load_profile)
    load_profile_button.grid(row=7, column=1, padx=5, pady=10)

    # Create generate button
    generate_button = ttk.Button(root, text="Generate Password List", command=save_password_list)
    generate_button.grid(row=8, column=0, columnspan=2, pady=10)

    # Create progress bar
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=200, mode='determinate', variable=progress_var)
    progress_bar.grid(row=9, column=0, columnspan=2, pady=10)

    # Create status text
    status_text = tk.StringVar()
    status_label = ttk.Label(root, textvariable=status_text)
    status_label.grid(row=10, column=0, columnspan=2)

    root.mainloop()

if __name__ == "__main__":
    generate_password_list_gui()
