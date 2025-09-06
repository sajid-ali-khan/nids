# NIDS (Network Intrusion Detection System)
## Steps to install
1. Clone the repository
2. Create a python virtual environment with name `myenv`
3. Activate this python virtual environment with `source ./.myenv/bin/activate` (ubuntu) or `.\.myenv\Scripts\activate.bat`(windows)
4. Install the dependencies with `pip install -r requirements.txt`
5. Upload the `model.pt` and `scaler.pkl` inside a `./model` folder
6. Run `./.myenv/bin/python3 predict.py` with root privilege
