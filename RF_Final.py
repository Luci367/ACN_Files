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
df = pd.read_csv('./train_data.csv')
df_test = pd.read_csv('./test_data.csv')

print('Dimensions of the Training set:', df.shape)
print('Dimensions of the Test set:', df_test.shape)

print('Label distribution Training set:')
print(df['Label'].value_counts())
print()

print('Class distribution Training set:')
print(df['Class'].value_counts())
print()

print('Label distribution Test set:')
print(df_test['Label'].value_counts())
print()

print('Class distribution Test set:')
print(df_test['Class'].value_counts())

print('Training set:')
for col_name in df.columns:
    if df[col_name].dtypes == 'object':
        unique_cat = len(df[col_name].unique())
        print("Feature '{col_name}' has {unique_cat} categories".format(col_name=col_name, unique_cat=unique_cat))

print()

# Test set
print('Test set:')
for col_name in df_test.columns:
    if df_test[col_name].dtypes == 'object':
        unique_cat = len(df_test[col_name].unique())
        print("Feature '{col_name}' has {unique_cat} categories".format(col_name=col_name, unique_cat=unique_cat))

print()
print('Distribution of categories in Label:')
print(df['Label'].value_counts().sort_values(ascending=False).head())

categorical_columns = ['Label', 'Class']

df_categorical_values = df[categorical_columns]
testdf_categorical_values = df_test[categorical_columns]

print(df_categorical_values.head())

# Label type
unique_Label = sorted(df.Label.unique())
string1 = 'Label_type_'
unique_Label2 = [string1 + x for x in unique_Label]
print(unique_Label2)

# Class type
unique_Class = sorted(df.Class.unique())
string1_Class = 'Class_type_'
unique_Class2 = [string1_Class + x for x in unique_Class]
print(unique_Class2)

dumcols = unique_Label2 + unique_Class2

# TEST SET

# Label type
unique_Label_test = sorted(df_test.Label.unique())
string1_test = 'Label_type_'
unique_Label2_test = [string1_test + x for x in unique_Label_test]
print(unique_Label2_test)

# Class type
unique_Class_test = sorted(df_test.Class.unique())
string1_Class_test = 'Class_type_'
unique_Class2_test = [string1_Class_test + x for x in unique_Class_test]
print(unique_Class2_test)

testdumcols = unique_Label2_test + unique_Class2_test

df_categorical_values_enc = df_categorical_values.apply(LabelEncoder().fit_transform)

print(df_categorical_values.head())
print('--------------------')
print(df_categorical_values_enc.head())

# test set
testdf_categorical_values_enc = testdf_categorical_values.apply(LabelEncoder().fit_transform)

enc = OneHotEncoder(categories='auto')
df_categorical_values_encenc = enc.fit_transform(df_categorical_values_enc)
df_cat_data = pd.DataFrame(df_categorical_values_encenc.toarray(), columns=dumcols)

# test set
testdf_categorical_values_encenc = enc.fit_transform(testdf_categorical_values_enc)
testdf_cat_data = pd.DataFrame(testdf_categorical_values_encenc.toarray(), columns=testdumcols)

print(df_cat_data.head())

##Joining the new data

newdf = df.join(df_cat_data)
newdf_test = df_test.join(testdf_cat_data)

labeldf = df['Label'].unique()
print(labeldf)

print(newdf.shape)
print(newdf_test.shape)

labeldf = newdf['Label']
labeldf_test = newdf_test['Label']

newlabeldf = labeldf.replace({
    'Benign': 0,
    'DrDoS_NTP': 1,
    'DrDoS_UDP': 2,
    'DrDoS_MSSQL': 3,
    'DrDoS_SNMP': 4,
    'DrDoS_DNS': 5,
    'DrDoS_LDAP': 6,
    'DrDoS_NetBIOS': 7,
    'WebDDoS': 8,
    'TFTP': 9,
    'LDAP': 10,
    'UDP': 11,
    'Syn': 12,
    'MSSQL': 13,
    'UDP-lag': 14,
    'Portmap': 15,
    'NetBIOS': 16,
    'UDPLag': 17
})

newlabeldf_test = labeldf_test.replace({
    'Benign': 0,
    'DrDoS_NTP': 1,
    'DrDoS_UDP': 2,
    'DrDoS_MSSQL': 3,
    'DrDoS_SNMP': 4,
    'DrDoS_DNS': 5,
    'DrDoS_LDAP': 6,
    'DrDoS_NetBIOS': 7,
    'WebDDoS': 8,
    'TFTP': 9,
    'LDAP': 10,
    'UDP': 11,
    'Syn': 12,
    'MSSQL': 13,
    'UDP-lag': 14,
    'Portmap': 15,
    'NetBIOS': 16,
    'UDPLag': 17
})

classdf = newdf['Class']
classdf_test = newdf_test['Class']

newclassdf = classdf.replace({
    'Benign': 0,
    'Attack': 1
})

newclassdf_test = classdf_test.replace({
    'Benign': 0,
    'Attack': 1
})

newdf['Label'] = newlabeldf
newdf_test['Label'] = newlabeldf_test

newdf['Class'] = newclassdf
newdf_test['Class'] = newclassdf_test

label_type_cols_to_drop = [
    'Label_type_Benign', 'Label_type_DrDoS_NTP', 'Label_type_DrDoS_NetBIOS', 'Label_type_DrDoS_SNMP',
    'Label_type_DrDoS_UDP', 'Label_type_NetBIOS', 'Label_type_Portmap', 'Label_type_Syn',
    'Label_type_TFTP', 'Label_type_UDP', 'Label_type_UDP-lag', 'Label_type_UDPLag', 'Label_type_WebDDoS', 'Unnamed: 0',
    'Label_type_DrDoS_DNS', 'Label_type_DrDoS_LDAP','Label_type_DrDoS_MSSQL', 'Label_type_LDAP', 'Label_type_MSSQL',
    'Class_type_Attack','Class_type_Benign'
]

newdf = newdf.drop(columns=label_type_cols_to_drop, axis=1)
newdf_test = newdf_test.drop(columns=label_type_cols_to_drop, axis=1)


X = newdf.drop(['Label', 'Class'], axis=1)
Y = newdf[['Label']]

X_test = newdf_test.drop(['Label', 'Class'], axis=1)
Y_test = newdf_test[['Label']]

colNames = list(X)
colNames_test = list(X_test)

scaler = preprocessing.StandardScaler().fit(X)
X_scaled = scaler.transform(X)

Y = Y.values.ravel()
Y_test = Y_test.values.ravel()

clf = RandomForestClassifier(n_estimators=10,n_jobs=2)
rfe = RFE(estimator=clf, n_features_to_select=13, step=1)

rfe.fit(X, Y.astype(int))
X_rfe = rfe.transform(X)
true = rfe.support_
rfecolindex = [i for i, x in enumerate(true) if x]
rfecolname= list(colNames[i] for i in rfecolindex)

print('Features selected for DDoS:', rfecolname)
print()

print(X_rfe.shape)

clf_DDoS = RandomForestClassifier(n_estimators=10, n_jobs=2)
clf_DDoS.fit(X, Y.astype(int))

clf_rfeDDoS = RandomForestClassifier(n_estimators=10, n_jobs=2)
clf_rfeDDoS.fit(X_rfe, Y.astype(int))

clf_DDoS.predict(X_test)
clf_DDoS.predict_proba(X_test)[0:10]
Y_pred = clf_DDoS.predict(X_test)

X_test2 = X_test.iloc[:, rfecolindex]
Y_rfe_pred = clf_rfeDDoS.predict(X_test2)



##
# rfe = RFE(estimator=RandomForestClassifier(n_estimators=10, n_jobs=2), n_features_to_select=13, step=1)
# rfe.fit(X_scaled, Y.astype(int))
# X_rfe = rfe.transform(X_scaled)

# print('Features selected:', list(colNames[i] for i in range(len(colNames)) if rfe.support_))
# print(X_rfe.shape)

# clf = RandomForestClassifier(n_estimators=10, n_jobs=2)
# clf.fit(X_scaled, Y.astype(int))

# clf_rfe = RandomForestClassifier(n_estimators=10, n_jobs=2)
# clf_rfe.fit(X_rfe, Y.astype(int))

# Y_pred = clf.predict(X_test)
# Y_rfe_pred = clf_rfe.predict(X_test)

# Evaluate the models
print("Random Forest Classifier:")
print("Accuracy:", metrics.accuracy_score(Y_test.astype(int), Y_pred))
# print("Precision:", metrics.precision_score(Y_test.astype(int), Y_pred))
# print("Recall:", metrics.recall_score(Y_test.astype(int), Y_pred))
# print("F1 Score:", metrics.f1_score(Y_test.astype(int), Y_pred))

#neeche wala use karna
# print("Precision:", metrics.precision_score(Y_test.astype(int), Y_pred, average='weighted'))
print("\nRandom Forest Classifier with RFE:")
print("Accuracy:", metrics.accuracy_score(Y_test.astype(int), Y_rfe_pred))
# print("Precision:", metrics.precision_score(Y_test.astype(int), Y_rfe_pred))
# print("Recall:", metrics.recall_score(Y_test.astype(int), Y_rfe_pred))
# print("F1 Score:", metrics.f1_score(Y_test.astype(int), Y_rfe_pred))
