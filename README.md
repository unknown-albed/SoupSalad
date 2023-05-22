# SoupSalad

The Password List Generator is a Python application built using the tkinter library. It allows users to generate a list of passwords based on their profile information. The application provides an intuitive GUI where users can enter their name, surname, city, birthdate, and define the minimum and maximum characters for the passwords. Users can also specify additional special characters to include in the password generation process.

The application utilizes the itertools library to generate all possible combinations of characters based on the provided profile information and length range. The generated passwords are saved to a text file, allowing users to easily obtain a list of potential passwords for various purposes.

Key Features:

User-friendly GUI for entering profile information and generating passwords.
Ability to save the generated password list to a text file.
Support for defining the minimum and maximum character lengths for the passwords.
Option to include additional special characters in the password generation process.
Progress bar and status updates to track the password generation progress.
Support for saving and loading user profiles to quickly populate the input fields.
This Password List Generator provides a convenient way to generate a customized list of potential passwords based on user-defined parameters. It can be used for various purposes, such as password testing, generating password options for multiple accounts, or creating password dictionaries for security analysis.

Feel free to customize and enhance the application further to suit your specific requirements.

Happy coding!

Step-by-step instructions on how to use the Password List Generator:

1. Clone the Repository:
   - Open your command-line interface (CLI) or terminal.
   - Navigate to the directory where you want to clone the repository.
   - Execute the following command: `git clone https://github.com/your-username/Password-List-Generator.git`
   - The repository will be cloned to your local machine.

2. Install Dependencies:
   - Ensure that you have Python installed on your machine (version 3.6 or above).
   - Open your CLI or terminal and navigate to the cloned repository's directory.
   - Execute the following command to install the required dependencies: `pip install -r requirements.txt`

3. Launch the Application:
   - In the same CLI or terminal, execute the following command: `python password_list_generator.py`
   - The Password List Generator application window will open.

4. Enter Profile Information:
   - In the application window, enter your profile information in the corresponding input fields.
   - Provide your name, surname, city, birthdate, minimum and maximum characters for passwords, and optional special characters.
   - Ensure that all mandatory fields (name, surname, city) are filled in.

5. Generate Password List:
   - Click on the "Generate Password List" button to start generating the password list.
   - The application will display a progress bar indicating the completion percentage.
   - You can pause the password generation process by clicking the "Generate Password List" button again.

6. Save the Password List:
   - After the password generation is complete, a file dialog will open.
   - Choose the directory where you want to save the generated password list.
   - Enter a filename for the password list file.
   - Click the "Save" button to save the password list to the selected location.

7. Save and Load Profiles (Optional):
   - You can save and load profiles to quickly populate the input fields.
   - Click on the "Save Profile" button to save the current profile information to a profile file.
   - Click on the "Load Profile" button to load a previously saved profile file.

8. Exit the Application:
   - To exit the Password List Generator, simply close the application window.

That's it! You can now use the Password List Generator to generate customized password lists based on your profile information. Feel free to explore the application's features and customize it further to suit your needs.
