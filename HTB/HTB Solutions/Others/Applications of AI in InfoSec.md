ons and their Answers

| Section                                         | Question Number | Answer                                   |
| ----------------------------------------------- | --------------- | ---------------------------------------- |
| Environment Setup                               | Question 1      | DONE                                     |
| Model Evaluation (Spam Detection)               | Question 1      | HTB{sp4m\_cla55if13r\_3v4lu4t0r}         |
| Model Evaluation (Network Anomaly Detection)    | Question 1      | HTB{n3tw0rk\_tr4ff1c\_4n0m4ly\_d3t3ct0r} |
| Model Evaluation (Malware Image Classification) | Question 1      | HTB{9569648083a8106ba057bbbe2d00d8ec}    |
| Skills Assessment                               | Question 1      | HTB{s3nt1m3nt\_4n4lys1s\_d4t4}           |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Model Evaluation (Spam Detection)

## Question 1

### "What is the flag you get from submitting a good model for evaluation?"

After spawning the target, students will create a work directory and install the `conda` package manager on their workstations:

Code: shell

```shell
mkdir work
cd work/
wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh -b -u
eval "$(/home/$USER/miniconda3/bin/conda shell.$(ps -p $$ -o comm=) hook)"
```

```
┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~]
└──╼ [★]$ mkdir work
┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~]
└──╼ [★]$ cd work
┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~/work]
└──╼ [★]$ wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~/work]
└──╼ [★]$ ./Miniconda3-latest-Linux-x86_64.sh -b -u

PREFIX=/home/htb-ac-8414/miniconda3
Unpacking payload ...

Installing base environment...

Preparing transaction: ...working... done
Executing transaction: ...working... done
installation finished.

┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~/work]
└──╼ [★]$ eval "$(/home/$USER/miniconda3/bin/conda shell.$(ps -p $$ -o comm=) hook)"
```

Subsequently, students will install the following Python3 libraries:

Code: shell

```shell
pip3 install nltk
pip3 install pandas
pip3 install scikit-learn scipy matplotlib
```

```
(base) ┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~/work]
└──╼ [★]$ pip3 install nltk

Collecting nltk
  Downloading nltk-3.9.1-py3-none-any.whl.metadata (2.9 kB)
Collecting click (from nltk)
  Downloading click-8.1.8-py3-none-any.whl.metadata (2.3 kB)
Collecting joblib (from nltk)
  Downloading joblib-1.4.2-py3-none-any.whl.metadata (5.4 kB)
Collecting regex>=2021.8.3 (from nltk)
  <SNIP>
  
(base) ┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~/work]
└──╼ [★]$ pip3 install pandas

Collecting pandas
  Downloading pandas-2.2.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (89 kB)
Collecting numpy>=1.26.0 (from pandas)
  Downloading numpy-2.2.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (62 kB)
<SNIP>

(base) ┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~/work]
└──╼ [★]$ pip3 install scikit-learn scipy matplotlib

Collecting scikit-learn
  Downloading scikit_learn-1.6.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (18 kB)
Collecting scipy
  Downloading scipy-1.15.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (61 kB)
Collecting matplotlib
  Downloading matplotlib-3.10.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (11 kB)
Requirement already satisfied: numpy>=1.19.5 in /home/htb-ac-8414/miniconda3/lib/python3.12/site-packages (from scikit-learn) (2.2.1)
<SNIP>
```

Next, students will reuse the provided Python3 code snippets from `The Spam Dataset`, `Preprocessing the Spam Dataset`, `Feature Extraction`, and the `Training and Evaluation (Spam Detection)` sections, ending up with a similar to the following Python3 script to create the training model:

Code: python

```python
import os
import re
import nltk
import pandas as pd
import numpy as np
import requests
import zipfile
import io
import joblib
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

# Download and extract dataset
def download_dataset(url, extract_to):
    response = requests.get(url)
    if response.status_code == 200:
        print("Download successful")
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(extract_to)
            print("Extraction successful")
    else:
        print("Failed to download the dataset")

# Preprocess messages
def preprocess_message(message, stop_words, stemmer):
    message = message.lower()
    message = re.sub(r"[^a-z\s$!]", "", message)
    tokens = word_tokenize(message)
    tokens = [word for word in tokens if word not in stop_words]
    tokens = [stemmer.stem(word) for word in tokens]
    return " ".join(tokens)

# Load and preprocess dataset
def load_and_preprocess_data(file_path):
    df = pd.read_csv(file_path, sep="\t", header=None, names=["label", "message"])
    df.drop_duplicates(inplace=True)

    nltk.download("punkt_tab")
    nltk.download("stopwords")
    stop_words = set(stopwords.words("english"))
    stemmer = PorterStemmer()

    df["message"] = df["message"].apply(lambda x: preprocess_message(x, stop_words, stemmer))
    df["label"] = df["label"].apply(lambda x: 1 if x == "spam" else 0)

    return df

# Train and evaluate the model
def train_model(df):
    X = df["message"]
    y = df["label"]

    vectorizer = CountVectorizer(min_df=1, max_df=0.9, ngram_range=(1, 2))
    pipeline = Pipeline([
        ("vectorizer", vectorizer),
        ("classifier", MultinomialNB())
    ])

    param_grid = {"classifier__alpha": [0.01, 0.1, 0.15, 0.2, 0.25, 0.5, 0.75, 1.0]}
    grid_search = GridSearchCV(pipeline, param_grid, cv=5, scoring="f1")
    grid_search.fit(X, y)

    best_model = grid_search.best_estimator_
    print("Best model parameters:", grid_search.best_params_)

    return best_model

# Save the model
def save_model(model, filename):
    joblib.dump(model, filename)
    print(f"Model saved to {filename}")

# Load the model
def load_model(filename):
    return joblib.load(filename)

# Predict new messages
def predict_messages(model, messages):
    predictions = model.predict(messages)
    probabilities = model.predict_proba(messages)

    for i, msg in enumerate(messages):
        prediction = "Spam" if predictions[i] == 1 else "Not-Spam"
        spam_probability = probabilities[i][1]
        ham_probability = probabilities[i][0]

        print(f"Message: {msg}")
        print(f"Prediction: {prediction}")
        print(f"Spam Probability: {spam_probability:.2f}")
        print(f"Not-Spam Probability: {ham_probability:.2f}")
        print("-" * 50)

if __name__ == "__main__":
    # Dataset URL and extraction path
    dataset_url = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
    extract_path = "sms_spam_collection"

    # Download and prepare dataset
    download_dataset(dataset_url, extract_path)
    dataset_path = os.path.join(extract_path, "SMSSpamCollection")
    df = load_and_preprocess_data(dataset_path)

    # Train model
    model = train_model(df)

    # Save model
    save_model(model, "spam_detection_model.joblib")

    # Example usage
    new_messages = [
        "Congratulations! You've won a $1000 Walmart gift card. Go to http://bit.ly/1234 to claim now.",
        "Hey, are we still meeting up for lunch today?",
        "Urgent! Your account has been compromised. Verify your details here: www.fakebank.com/verify",
        "Reminder: Your appointment is scheduled for tomorrow at 10am.",
        "FREE entry in a weekly competition to win an iPad. Just text WIN to 80085 now!",
    ]

    # Load and predict
    loaded_model = load_model("spam_detection_model.joblib")
    predict_messages(loaded_model, new_messages)
```

Students will execute the Python3 script to generate the `spam_detection_model.joblib` file:

Code: shell

```shell
python3 training_model.py 
```

```
(base) ┌─[eu-academy-6]─[10.10.14.201]─[htb-ac-8414@htb-sdjfh2zwcj]─[~/work]
└──╼ [★]$ python3 training_model.py 

Download successful
Extraction successful
[nltk_data] Downloading package punkt_tab to /home/htb-
[nltk_data]     ac-8414/nltk_data...
[nltk_data]   Package punkt_tab is already up-to-date!
[nltk_data] Downloading package stopwords to /home/htb-
[nltk_data]     ac-8414/nltk_data...
[nltk_data]   Package stopwords is already up-to-date!
Best model parameters: {'classifier__alpha': 0.25}
Model saved to spam_detection_model.joblib
Message: Congratulations! You've won a $1000 Walmart gift card. Go to http://bit.ly/1234 to claim now.
Prediction: Not-Spam
Spam Probability: 0.39
Not-Spam Probability: 0.61
--------------------------------------------------
Message: Hey, are we still meeting up for lunch today?
Prediction: Not-Spam
Spam Probability: 0.00
Not-Spam Probability: 1.00
--------------------------------------------------
Message: Urgent! Your account has been compromised. Verify your details here: www.fakebank.com/verify
Prediction: Not-Spam
Spam Probability: 0.18
Not-Spam Probability: 0.82
--------------------------------------------------
Message: Reminder: Your appointment is scheduled for tomorrow at 10am.
Prediction: Not-Spam
Spam Probability: 0.01
Not-Spam Probability: 0.99
--------------------------------------------------
Message: FREE entry in a weekly competition to win an iPad. Just text WIN to 80085 now!
Prediction: Spam
Spam Probability: 1.00
Not-Spam Probability: 0.00
--------------------------------------------------
```

Subsequently, students will open `Firefox` and navigate to `http://STMIP:8000` to upload the module (`spam_detection_model.joblib`):

![[HTB Solutions/Others/z. images/8f9813cf2f8ab163188f4556c4c40506_MD5.jpg]]

Students will click on the `Upload Model` button to obtain the flag:

![[HTB Solutions/Others/z. images/d2568e9916009cf4631ba5a8dda8a5f2_MD5.jpg]]

Answer: `HTB{sp4m_cla55if13r_3v4lu4t0r}`

# Model Evaluation (Network Anomaly Detection)

## Question 1

### "What is the flag you get from submitting a good model for evaluation?"

After spawning the target, students will create a work directory and install the `conda` package manager on their workstations:

Code: shell

```shell
mkdir work
cd work/
wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh -b -u
eval "$(/home/$USER/miniconda3/bin/conda shell.$(ps -p $$ -o comm=) hook)"
```

```
┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~]
└──╼ [★]$ mkdir work
┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~]
└──╼ [★]$ cd work/
┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ chmod +x Miniconda3-latest-Linux-x86_64.sh
┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ ./Miniconda3-latest-Linux-x86_64.sh -b -u

PREFIX=/home/htb-ac-8414/miniconda3
Unpacking payload ...

Installing base environment...

Preparing transaction: ...working... done
Executing transaction: ...working... done
installation finished.

┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ eval "$(/home/$USER/miniconda3/bin/conda shell.$(ps -p $$ -o comm=) hook)"
```

Next, students will download the `KDD_dataset.zip` (https://academy.hackthebox.com/storage/modules/292/KDD\_dataset.zip) on their workstations using `wget` and will unzip the archive:

Code: shell

```shell
wget -q https://academy.hackthebox.com/storage/modules/292/KDD_dataset.zip
unzip KDD_dataset.zip
```

```
(base) ┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ wget -q https://academy.hackthebox.com/storage/modules/292/KDD_dataset.zip
(base) ┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ unzip KDD_dataset.zip

Archive:  KDD_dataset.zip
  inflating: KDD+.txt   
```

Subsequently, students will install the following Python3 libraries:

Code: shell

```shell
pip3 install nltk
pip3 install pandas
pip3 install scikit-learn scipy matplotlib
pip3 install seaborn
```

```
(base) ┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ pip3 install nltk

Collecting nltk
  Downloading nltk-3.9.1-py3-none-any.whl.metadata (2.9 kB)
Collecting click (from nltk)
  Downloading click-8.1.8-py3-none-any.whl.metadata (2.3 kB)
Collecting joblib (from nltk)
  Downloading joblib-1.4.2-py3-none-any.whl.metadata (5.4 kB)
Collecting regex>=2021.8.3 (from nltk)

<SNIP>

(base) ┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ pip3 install pandas

Collecting pandas
  Downloading pandas-2.2.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (89 kB)
Collecting numpy>=1.26.0 (from pandas)

<SNIP>

(base) ┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ pip3 install scikit-learn scipy matplotlib

Collecting scikit-learn
  Downloading scikit_learn-1.6.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (18 kB)
Collecting scipy
  Downloading scipy-1.15.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (61 kB)
Collecting matplotlib

<SNIP>

(base) ┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ pip3 install seaborn

Collecting seaborn
  Downloading seaborn-0.13.2-py3-none-any.whl.metadata (5.4 kB)
Requirement already satisfied: numpy!=1.24.0,>=1.20 in /home/htb-ac-8414/miniconda3/lib/python3.12/site-packages (from seaborn) (2.2.2)

<SNIP>
```

Next, students will reuse the provided Python3 code snippets from `Network Anomaly Dataset`, `Preprocessing and Splitting the Dataset`, and the `Training and Evaluation (Network Anomaly Detection)` sections, ending up with the following Python3 script to create the training model:

Code: python

```python
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt
import joblib

# Set the file path to the dataset
file_path = r'KDD+.txt'

# Define the column names corresponding to the NSL-KDD dataset
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack', 'level'
]

# Read the combined NSL-KDD dataset into a DataFrame
df = pd.read_csv(file_path, names=columns)

print(df.head())

# Binary classification target
# Maps normal traffic to 0 and any type of attack to 1
df['attack_flag'] = df['attack'].apply(lambda a: 0 if a == 'normal' else 1)

# Multi-class classification target categories
dos_attacks = ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 
               'processtable', 'smurf', 'teardrop', 'udpstorm', 'worm']
probe_attacks = ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan']
privilege_attacks = ['buffer_overflow', 'loadmdoule', 'perl', 'ps', 
                     'rootkit', 'sqlattack', 'xterm']
access_attacks = ['ftp_write', 'guess_passwd', 'http_tunnel', 'imap', 
                  'multihop', 'named', 'phf', 'sendmail', 'snmpgetattack', 
                  'snmpguess', 'spy', 'warezclient', 'warezmaster', 
                  'xclock', 'xsnoop']

def map_attack(attack):
    if attack in dos_attacks:
        return 1
    elif attack in probe_attacks:
        return 2
    elif attack in privilege_attacks:
        return 3
    elif attack in access_attacks:
        return 4
    else:
        return 0

# Assign multi-class category to each row
df['attack_map'] = df['attack'].apply(map_attack)

# Encoding categorical variables
features_to_encode = ['protocol_type', 'service']
encoded = pd.get_dummies(df[features_to_encode])

# Numeric features that capture various statistical properties of the traffic
numeric_features = [
    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent', 'hot', 
    'num_failed_logins', 'num_compromised', 'root_shell', 'su_attempted', 
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
    'num_outbound_cmds', 'count', 'srv_count', 'serror_rate', 
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
    'dst_host_srv_rerror_rate'
]

# Combine encoded categorical variables and numeric features
train_set = encoded.join(df[numeric_features])

# Multi-class target variable
multi_y = df['attack_map']

# Split data into training and test sets for multi-class classification
train_X, test_X, train_y, test_y = train_test_split(train_set, multi_y, test_size=0.2, random_state=1337)

# Further split the training set into separate training and validation sets
multi_train_X, multi_val_X, multi_train_y, multi_val_y = train_test_split(train_X, train_y, test_size=0.3, random_state=1337)

# Train RandomForest model for multi-class classification
rf_model_multi = RandomForestClassifier(random_state=1337)
rf_model_multi.fit(multi_train_X, multi_train_y)

# Predict and evaluate the model on the validation set
multi_predictions = rf_model_multi.predict(multi_val_X)
accuracy = accuracy_score(multi_val_y, multi_predictions)
precision = precision_score(multi_val_y, multi_predictions, average='weighted')
recall = recall_score(multi_val_y, multi_predictions, average='weighted')
f1 = f1_score(multi_val_y, multi_predictions, average='weighted')

print(f"Validation Set Evaluation:")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-Score: {f1:.4f}")

# Confusion Matrix for validation set
conf_matrix = confusion_matrix(multi_val_y, multi_predictions)
class_labels = ['Normal', 'DoS', 'Probe', 'Privilege', 'Access']
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_labels,
            yticklabels=class_labels)
plt.title('Network Anomaly Detection - Validation Set')
plt.xlabel('Predicted')
plt.ylabel('Actual')
#plt.show()

# Classification report for Validation Set
print("Classification Report for Validation Set")
print(classification_report(multi_val_y, multi_predictions, target_names=class_labels))

# Final evaluation on the test set

test_multi_predictions = rf_model_multi.predict(test_X)
test_accuracy = accuracy_score(test_y, test_multi_predictions)
test_precision = precision_score(test_y, test_multi_predictions, average='weighted')
test_recall = recall_score(test_y, test_multi_predictions, average='weighted')
test_f1 = f1_score(test_y, test_multi_predictions, average='weighted')

print(f"\nTest Set Evaluation:")
print(f"Accuracy: {test_accuracy:.4f}")
print(f"Precision: {test_precision:.4f}")
print(f"Recall: {test_recall:.4f}")
print(f"F1-Score: {test_f1:.4f}")

# Confusion Matrix for Test Set
test_conf_matrix = confusion_matrix(test_y, test_multi_predictions)
sns.heatmap(test_conf_matrix, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_labels,
            yticklabels=class_labels)

plt.title('Network Anomaly Detection')
plt.xlabel('Predicted')
plt.ylabel('Actual')
#plt.show

# Classification Report for Test Set
print("Classification Report for Test Set:")
print(classification_report(test_y, test_multi_predictions, target_names=class_labels))

# Save the trained model to a file
model_filename = 'network_anomaly_detection_model.joblib'
joblib.dump(rf_model_multi, model_filename)

print(f"Model saved to {model_filename}")
```

Students will execute the Python3 script to generate the `network_anomaly_detection_model.joblib` file:

Code: shell

```shell
python3 training_model.py 
```

```
(base) ┌─[eu-academy-6]─[10.10.14.103]─[htb-ac-8414@htb-0jmbkwyzyk]─[~/work]
└──╼ [★]$ python3 training_model.py

   duration protocol_type   service  ... dst_host_srv_rerror_rate   attack  level
0         0           tcp  ftp_data  ...                     0.00   normal     20
1         0           udp     other  ...                     0.00   normal     15
2         0           tcp   private  ...                     0.00  neptune     19
3         0           tcp      http  ...                     0.01   normal     21
4         0           tcp      http  ...                     0.00   normal     21

[5 rows x 43 columns]
Validation Set Evaluation:
Accuracy: 0.9950
Precision: 0.9949
Recall: 0.9950
F1-Score: 0.9949

<SNIP>

Model saved to network_anomaly_detection_model.joblib
```

Subsequently, students will open `Firefox` and navigate to `http://STMIP:8001` to upload the module (`network_anomaly_detection_model.joblib`):

![[HTB Solutions/Others/z. images/0224c4d3f87661a1902ce348dc24c809_MD5.jpg]]

Students will click on the `Upload Model` button to obtain the flag:

![[HTB Solutions/Others/z. images/6564227d67a4ba5b3e9381482b0646de_MD5.jpg]]

Answer: `HTB{n3tw0rk_tr4ff1c_4n0m4ly_d3t3ct0r}`

# Model Evaluation (Malware Image Classification)

## Question 1

### "What is the flag you get from submitting a good model for evaluation?"

After spawning the target, students will open `Firefox`, navigate to `http://STMIP:8888`, use the `JupyterLab` instance, and use the `Python 3 (ipykernel)` notebook:

![[HTB Solutions/Others/z. images/552a049b8ab488e9718aa99cc371a11d_MD5.jpg]]

Students will use the `splitfolders` Python library to split the data, where 80% will be used for training, and the other 20% will be used for testing. They will use the following code and run the code in the cell:

```python
import splitfolders

DATA_BASE_PATH = "./malimg_paper_dataset_imgs/"
TARGET_BASE_PATH = "./newdata/"

TRAINING_RATIO = 0.8
TEST_RATIO = 1 - TRAINING_RATIO

splitfolders.ratio(input=DATA_BASE_PATH, output=TARGET_BASE_PATH, ratio=(TRAINING_RATIO, 0, TEST_RATIO))
```

![[HTB Solutions/Others/z. images/5c2cee7ee2fd9f3d1a3e2f1e5e015b3a_MD5.jpg]]

Next, students will apply preprocessing and create data loaders for the model to read the data, normalize it, and standardize it:

```python
from torchvision import transforms
from torch.utils.data import DataLoader
from torchvision.datasets import ImageFolder
import os

def load_datasets(base_path, train_batch_size, test_batch_size):
    # Define preprocessing transforms
    transform = transforms.Compose([
        transforms.Resize((75, 75)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ])

    # Load training and test datasets
    train_dataset = ImageFolder(
        root=os.path.join(base_path, "train"),
        transform=transform
    )

    test_dataset = ImageFolder(
        root=os.path.join(base_path, "test"),
        transform=transform
    )

    # Create data loaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=train_batch_size,
        shuffle=True,
        num_workers=2
    )
    
    test_loader = DataLoader(
        test_dataset,
        batch_size=test_batch_size,
        shuffle=False,
        num_workers=2
    )

    n_classes = len(train_dataset.classes)
    return train_loader, test_loader, n_classes
```

![[HTB Solutions/Others/z. images/a8abde0b591421cc93f88408582f5651_MD5.jpg]]

Students will utilize the `ResNet50` model of Convolutional Neural Network (CNN) to speed up the training process:

```python
import torch.nn as nn
import torchvision.models as models

HIDDEN_LAYER_SIZE = 1000

class MalwareClassifier(nn.Module):
    def __init__(self, n_classes):
        super(MalwareClassifier, self).__init__()
        # Load pretrained ResNet50
        self.resnet = models.resnet50(weights='DEFAULT')
        
        # Freeze ResNet parameters
        for param in self.resnet.parameters():
            param.requires_grad = False
        
        # Replace the last fully connected layer
        num_features = self.resnet.fc.in_features
        self.resnet.fc = nn.Sequential(
            nn.Linear(num_features, HIDDEN_LAYER_SIZE),
            nn.ReLU(),
            nn.Linear(HIDDEN_LAYER_SIZE, n_classes)
        )

    def forward(self, x):
        return self.resnet(x)
```

![[HTB Solutions/Others/z. images/ffa218960e12abfc8eaa32d7b3ed2d62_MD5.jpg]]

They will utilize the advantage of dynamically setting the number of classes to be used from the dataset:

```python
DATA_PATH = "./newdata/"
TRAINING_BATCH_SIZE = 1024
TEST_BATCH_SIZE = 1024

# Load datasets
train_loader, test_loader, n_classes = load_datasets(DATA_PATH, TRAINING_BATCH_SIZE, TEST_BATCH_SIZE)

# Initialize model
model = MalwareClassifier(n_classes)
```

![[HTB Solutions/Others/z. images/a23692fcb89e60540a92a4ee2f5b2390_MD5.jpg]]

Students will define a training function by taking a model, a training loader, and the number of epochs using the Adam optimizer:

```python
import torch
import time

def train(model, train_loader, n_epochs, verbose=False):
    model.train()
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters())

    training_data = {"accuracy": [], "loss": []}
    
    for epoch in range(n_epochs):
        running_loss = 0
        n_total = 0
        n_correct = 0
        checkpoint = time.time() * 1000
        
        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            _, predicted = outputs.max(1)
            n_total += labels.size(0)
            n_correct += predicted.eq(labels).sum().item()
            running_loss += loss.item()
        
        epoch_loss = running_loss / len(train_loader)
        epoch_duration = int(time.time() * 1000 - checkpoint)
        epoch_accuracy = compute_accuracy(n_correct, n_total)
        
        training_data["accuracy"].append(epoch_accuracy)
        training_data["loss"].append(epoch_loss)
        
        if verbose:
            print(f"[i] Epoch {epoch+1} of {n_epochs}: Acc: {epoch_accuracy:.2f}% Loss: {epoch_loss:.4f} (Took {epoch_duration} ms).")    
    
    return training_data
```

![[HTB Solutions/Others/z. images/2111362e3f086de0f39871703a2c9b39_MD5.jpg]]

Students will define a function to save the model on disk (`JupyterLab`):

```python
def save_model(model, path):
	model_scripted = torch.jit.script(model)
	model_scripted.save(path)
```

![[HTB Solutions/Others/z. images/43e3ccb3344a6a302fce4c51ebd7890b_MD5.jpg]]

Subsequently, students will evaluate the model by defining a function returning the predicted class and are going to set the model into evaluation mode while disabling gradient calculation:

```python
def predict(model, test_data):
    model.eval()

    with torch.no_grad():
        output = model(test_data)
        _, predicted = torch.max(output.data, 1)

    return predicted
    
def compute_accuracy(n_correct, n_total):
    return round(100 * n_correct / n_total, 2)

def evaluate(model, test_loader):
    model.eval()

    n_correct = 0
    n_total = 0
    
    with torch.no_grad():
        for data, target in test_loader:
            predicted = predict(model, data)
            n_total += target.size(0)
            n_correct += (predicted == target).sum().item()

    accuracy = compute_accuracy(n_correct, n_total)  

    return accuracy
```

![[HTB Solutions/Others/z. images/47e0beee542af0c6021943622454d3ab_MD5.jpg]]

Next, students will load the data and perform initialization of the model, train the model and save the model to a file called `malware_classifier.pth`. Note that the whole process can take up to (or more) than an astronomical hour:

```python
# data parameters
DATA_PATH = "./newdata/"

# training parameters
N_EPOCHS = 10
TRAINING_BATCH_SIZE = 512
TEST_BATCH_SIZE = 1024

# model parameters
HIDDEN_LAYER_SIZE = 1000
MODEL_FILE = "malware_classifier.pth"

# Load datasets
train_loader, test_loader, n_classes = load_datasets(DATA_PATH, TRAINING_BATCH_SIZE, TEST_BATCH_SIZE)

# Initialize model
model = MalwareClassifier(n_classes)

# Train model
print("[i] Starting Training...")  
training_information = train(model, train_loader, N_EPOCHS, verbose=True)

# Save model
save_model(model, MODEL_FILE)

# evaluate model
accuracy = evaluate(model, test_loader)
print(f"[i] Inference accuracy: {accuracy}%.")  
```

![[HTB Solutions/Others/z. images/f74e5e889d312aeb987641196bb962e2_MD5.jpg]]

Students will proceed to use Python to upload the `malware_classifier.pth` file on port `8002` using the `/api/upload` API endpoint:

```python
import requests
import json

# Define the URL of the API endpoint
url = "http://localhost:8002/api/upload"

# Path to the model file you want to upload
model_file_path = "malware_classifier.pth"

# Open the file in binary mode and send the POST request
with open(model_file_path, "rb") as model_file:
    files = {"model": model_file}
    response = requests.post(url, files=files)

# Pretty print the response from the server
print(json.dumps(response.json(), indent=4))
```

![[HTB Solutions/Others/z. images/0c59de0975bf1da46543520e1b114e54_MD5.jpg]]

In the response, students will find the value of the flag in the `flag` parameter:

![[HTB Solutions/Others/z. images/34cf4438ddd9a574ffe363dcb8577d71_MD5.jpg]]

Answer: `HTB{9569648083a8106ba057bbbe2d00d8ec}`

# Skills Assessment

## Question 1

### "What is the flag you get from submitting a good model for evaluation?"

After spawning the target, students will manually download the `skills_assessment_data.zip` archive and unzip it. Subsequently, students will scrutinize the `train.json` data file and notice the presented data in JSON format. Further going through the data, they will take note of present HTML tags such as `<br /><br />` (line break), which students will consider when developing the Python3 script.

```txt
<SNIP>
I began watching this movie with my girl-friend. And after 5 minutes I was alone.<br /><br />I succeed to stay until the end. It has been a painful experience.<br /><br />I liked jean hugues anglade, but I think that he needed to eat, as us, and thus he accepted to play in this movie. <br /><br />There are only 5 characters, and the rest could be called 'art' or something that I couldn't express, but that I didn't understand at all.<br /><br />The only worst movie I saw was crash, but I'm pretty sure now that I have enough experience to watch it successfully again.<br /><br />good luck!! ;o)
<SNIP>
```

Students will create a work directory and install the `conda` package manager on their workstations:

```shell
mkdir work
cd work/
wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh -b -u
eval "$(/home/$USER/miniconda3/bin/conda shell.$(ps -p $$ -o comm=) hook)"
```
```
┌─[eu-academy-5]─[10.10.14.150]─[htb-ac-8414@htb-pt3bhl9zab]─[~]
└──╼ [★]$ mkdir work
cd work/
wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh -b -u
eval "$(/home/$USER/miniconda3/bin/conda shell.$(ps -p $$ -o comm=) hook)"
PREFIX=/home/htb-ac-8414/miniconda3
Unpacking payload ...

Installing base environment...

Preparing transaction: ...working... done
Executing transaction: ...working... done
installation finished.
```

Subsequently, students will install the following Python3 libraries:

```shell
pip3 install nltk
pip3 install pandas
pip3 install scikit-learn scipy matplotlib
```
```
(base) ┌─[eu-academy-5]─[10.10.14.150]─[htb-ac-8414@htb-pt3bhl9zab]─[~/work]
└──╼ [★]$ pip3 install nltk
pip3 install pandas
pip3 install scikit-learn scipy matplotlib

Collecting nltk
  Downloading nltk-3.9.1-py3-none-any.whl.metadata (2.9 kB)
Collecting click (from nltk)

<SNIP>
```

Students will utilize the Python3 code snippets from the `The Spam Dataset`, `Preprocessing the Spam Dataset`, `Feature Extraction`, and the `Training and Evaluating (Spam Detection)` sections, ending up with a similar Python3 script. The script will download the archive, initiate the dataset, and perform the necessary preprocessing, extraction, and model training. It utilizes the `CountVectorizer` feature extraction to convert the collection of text to a matrix of token counts while transforming the words to all lowercase, using stop words (and, the, etc.), denoting captured group content using regular expression for matching words (`\b\w+\b`). Students will also grab random sample data from `test.json` to be used for validating the prediction of the model stored in a list (`new_text`):

```python
import requests
import zipfile
import io
import pandas as pd
import re
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib
import sys
import json

def download():
    url = "https://academy.hackthebox.com/storage/modules/292/skills_assessment_data.zip"
    response = requests.get(url)
    if response.status_code == 200:
        print("Download successful")
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall("skills_assessment_data")
            print("Extraction successful")
    else:
        print("Failed to download the dataset")

def dataset():
    df = pd.read_json("skills_assessment_data/train.json", orient="records")
    df.info()
    # Drop duplicates
    df = df.drop_duplicates()
    return df

def clean_text(text):
    # Remove HTML tags
    text = re.sub(r"<.*?>", " ", text)
    # Remove non-word characters (punctuation, etc.) but keep spaces
    text = re.sub(r"[^\w\s]", " ", text)
    # Remove extra spaces
    text = re.sub(r"\s+", " ", text).strip()
    return text

def preprocessing(df):
    # Basic text cleaning
    df["text"] = df["text"].apply(lambda x: x.lower())
    df["text"] = df["text"].apply(clean_text)
    return df

def train_model(df):
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.3, random_state=42
    )

    # Create the pipeline
    pipeline = Pipeline([
        ("vectorizer", CountVectorizer(
            lowercase=True,
            stop_words="english",
            token_pattern=r"\b\w+\b",
            ngram_range=(1, 2)
        )),
        ("classifier", MultinomialNB())
    ])

    print("Training model...")
    pipeline.fit(X_train, y_train)
    print("Training complete!")

    # Save the trained model
    model_filename = "assessment.joblib"
    joblib.dump(pipeline, model_filename)
    print(f"Model saved to {model_filename}")

    return pipeline

def evaluate_model(model, new_texts):
    print("\nEvaluating new texts:")
    predictions = model.predict(new_texts)
    probabilities = model.predict_proba(new_texts)
    
    for text, pred, prob in zip(new_texts, predictions, probabilities):
        pred_label = "Good" if pred == 1 else "Bad"
        print(f"Text: {text[:60]}...")
        print(f"  -> Prediction: {pred_label} | Probabilities: {prob}")

def upload_model(pipeline):
    target = sys.argv[1]
    url = f'http://{target}:5000/api/upload'

    model_file_path = 'assessment.joblib'
    with open(model_file_path, "rb") as model_file:
        files = {"model": model_file}
        response = requests.post(url, files=files)

    # Pretty print the response from the server
    print(json.dumps(response.json(), indent=4))

if __name__ == "__main__":

    # Check for usage
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <target_ip>')
        sys.exit(1)

    target = sys.argv[1]

    download()
    df = dataset()
    df = preprocessing(df)

    # Train the model
    model = train_model(df)

    # Example new texts
    new_texts = [
        "I went and saw this movie last night after being coaxed to by a few friends of mine. I'll admit that I was reluctant to see it because from what I knew of Ashton Kutcher he was only able to do comedy. I was wrong. Kutcher played the character of Jake Fischer very well, and Kevin Costner played Ben Randall with such professionalism. The sign of a good movie is that it can toy with our emotions. This one did exactly that. The entire theater (which was sold out) was overcome by laughter during the first half of the movie, and were moved to tears during the second half. While exiting the theater I not only saw many women in tears, but many full grown men as well, trying desperately not to let anyone see them crying. This movie was great, and I suggest that you go see it before you judge.",
        "As a recreational golfer with some knowledge of the sport's history, I was pleased with Disney's sensitivity to the issues of class in golf in the early twentieth century. The movie depicted well the psychological battles that Harry Vardon fought within himself, from his childhood trauma of being evicted to his own inability to break that glass ceiling that prevents him from being accepted as an equal in English golf society. Likewise, the young Ouimet goes through his own class struggles, being a mere caddie in the eyes of the upper crust Americans who scoff at his attempts to rise above his standing. <br /><br />What I loved best, however, is how this theme of class is manifested in the characters of Ouimet's parents. His father is a working-class drone who sees the value of hard work but is intimidated by the upper class; his mother, however, recognizes her son's talent and desire and encourages him to pursue his dream of competing against those who think he is inferior.<br /><br />Finally, the golf scenes are well photographed. Although the course used in the movie was not the actual site of the historical tournament, the little liberties taken by Disney do not detract from the beauty of the film. There's one little Disney moment at the pool table; otherwise, the viewer does not really think Disney. The ending, as in \"Miracle,\" is not some Disney creation, but one that only human history could have written.",
        "Bill Paxton has taken the true story of the 1913 US golf open and made a film that is about much more than an extra-ordinary game of golf. The film also deals directly with the class tensions of the early twentieth century and touches upon the profound anti-Catholic prejudices of both the British and American establishments. But at heart the film is about that perennial favourite of triumph against the odds.<br /><br />The acting is exemplary throughout. Stephen Dillane is excellent as usual, but the revelation of the movie is Shia LaBoeuf who delivers a disciplined, dignified and highly sympathetic performance as a working class Franco-Irish kid fighting his way through the prejudices of the New England WASP establishment. For those who are only familiar with his slap-stick performances in \"Even Stevens\" this demonstration of his maturity is a delightful surprise. And Josh Flitter as the ten year old caddy threatens to steal every scene in which he appears.<br /><br />A old fashioned movie in the best sense of the word: fine acting, clear directing and a great story that grips to the end - the final scene an affectionate nod to Casablanca is just one of the many pleasures that fill a great movie."
    ]

    # Evaluate the model on new texts
    evaluate_model(model, new_texts)
    
    # Upload model and get flag
    upload_model(model)
```

Next, students will run the Python3 script and provide the IP address of the target to attain the flag value in the `flag` parameter in the response:

```shell
python3 assessment.py STMIP
```
```
(base) ┌─[eu-academy-5]─[10.10.14.150]─[htb-ac-8414@htb-pt3bhl9zab]─[~/work]
└──╼ [★]$ python3 assessment.py 10.129.205.188

Download successful
Extraction successful
<class 'pandas.core.frame.DataFrame'>
RangeIndex: 25000 entries, 0 to 24999
Data columns (total 2 columns):
 #   Column  Non-Null Count  Dtype 
---  ------  --------------  ----- 
 0   text    25000 non-null  object
 1   label   25000 non-null  int64 
dtypes: int64(1), object(1)
memory usage: 390.8+ KB
Training model...
Training complete!
Model saved to assessment.joblib

Evaluating new texts:
Text: I went and saw this movie last night after being coaxed to b...
  -> Prediction: Good | Probabilities: [1.12564277e-04 9.99887436e-01]
Text: As a recreational golfer with some knowledge of the sport's ...
  -> Prediction: Good | Probabilities: [3.30087643e-15 1.00000000e+00]
Text: Bill Paxton has taken the true story of the 1913 US golf ope...
  -> Prediction: Good | Probabilities: [2.6096601e-23 1.0000000e+00]
{
    "accuracy": 1.0,
    "flag": "{hidden}"
}
```

Answer: `HTB{s3nt1m3nt_4n4lys1s_d4t4}`