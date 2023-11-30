import pandas as pd
import numpy as np
import sys
import sklearn
import io
import random
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn import preprocessing
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn import metrics

print("Reading Data")
df = pd.read_csv('./cicddos2019_dataset.csv')
df.drop('Unnamed: 0',axis =1 ,inplace = True)

X = df.drop(['Label', 'Class'], axis=1)
Y = df[['Label']]

scaler = preprocessing.StandardScaler().fit(X)
X_scaled = scaler.transform(X)
Y = Y.values.ravel()

X_train,X_test,Y_train,Y_test = train_test_split(X, Y, test_size=.30,random_state =30)

colNames = list(X_train)
colNames_test = list(X_test)

clf = RandomForestClassifier(n_estimators=10,n_jobs=2)
rfe = RFE(estimator=clf, n_features_to_select=13, step=1)

rfe.fit(X_train, Y_train)
X_rfe = rfe.transform(X_train)
true = rfe.support_
rfecolindex = [i for i, x in enumerate(true) if x]
rfecolname= list(colNames[i] for i in rfecolindex)

print('Features selected for DDoS:', rfecolname)
print()

print(X_rfe.shape)

clf.fit(X_train, Y_train)

clf_rfeDDoS = RandomForestClassifier(n_estimators=10, n_jobs=2)
clf_rfeDDoS.fit(X_rfe, Y_train)

clf.predict(X_test)
Y_pred = clf.predict(X_test)

X_test2 = X_test.iloc[:, rfecolindex]
print(X_test2)
Y_rfe_pred = clf_rfeDDoS.predict(X_test2)

print("Random Forest Classifier:")
print("Accuracy:", metrics.accuracy_score(Y_test, Y_pred))

print("\nRandom Forest Classifier with RFE:")
print("Accuracy:", metrics.accuracy_score(Y_test, Y_rfe_pred))

