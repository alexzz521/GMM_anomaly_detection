import random

import torch
import numpy as np
import pandas as pd
from numpy import float64

from sklearn.preprocessing import MinMaxScaler

class basic_propress():
    def __init__(self,training_df,testing_df,col_name,name):
        self.training_df = training_df
        self.testing_df = testing_df
        self.col_name = col_name
        self.name = name


    def __setitem__(self, key, value):
        pass

    def __getitem__(self, item):
        pass



def minmax_scale_values(training_df,testing_df, col_name):
    scaler = MinMaxScaler()
    # scaler = scaler.fit(training_df[col_name].reshape(-1, 1))
    train_values_standardized = scaler.fit_transform(training_df[col_name].values.reshape(-1, 1))
    training_df[col_name] = train_values_standardized
    test_values_standardized = scaler.transform(testing_df[col_name].values.reshape(-1, 1))
    testing_df[col_name] = test_values_standardized


def encode_text(training_df, testing_df, name):
    training_set_dummies = pd.get_dummies(training_df[name])
    testing_set_dummies = pd.get_dummies(testing_df[name])
    for x in training_set_dummies.columns:
        dummy_name = "{}_{}".format(name, x)
        training_df[dummy_name] = training_set_dummies[x]
        if x in testing_set_dummies.columns:
            testing_df[dummy_name] = testing_set_dummies[x]
        else:
            testing_df[dummy_name] = np.zeros(len(testing_df))
    training_df.drop(name, axis=1, inplace=True)
    testing_df.drop(name, axis=1, inplace=True)

def label_attract(row,df_normal,df_malware):
    if (row["label"] == 1):
        return df_normal.append[row]
    else:
        return df_malware.append[row]

# def decide_normal(df,df_normal):
#     for label in range(df):
#         if (df["label"]==1):
#             df_normal.append[]

def _preData(x):
    scaler = MinMaxScaler()
    x_lable=x[:,-1]
    x_lable=x_lable[:, np.newaxis]
    train_normal_value = scaler.fit_transform(x[:,:-1])
    train_normal=np.hstack((train_normal_value,x_lable))
    return train_normal


def main_process():

    dataset = pd.read_csv("./unsw/smart_grid_stability_augmented.csv")


    normal = dataset[dataset['stabf'] == "stable"]
    normal = normal.drop(["stab"],axis=1)
    normal = normal.values
    normal = _preData(normal)

    allIndex = list(range(0, normal.shape[0] - 1))
    # print(allIndex)
    normalIndex = random.sample(allIndex, int(len(allIndex) * 0.9))
    # print(len(normalIndex))
    remainIndex = list(set(allIndex) - set(normalIndex))

    trainNormal = normal[normalIndex, :]
    print(trainNormal.shape)
    testNormal = normal[remainIndex, :]
    print(testNormal.shape)

    allmalware = dataset[dataset['stabf'] == "unstable"]
    allmalware  = allmalware .drop(["stab"], axis=1)
    allmalware = allmalware.values
    print(allmalware.shape)
    allmalware= _preData(allmalware)


    allmalIndex = list(range(0, allmalware.shape[0] - 1))
    malIndex = random.sample(allmalIndex, int(testNormal.shape[0] * 0.3))
    # malIndex = random.sample(allmalIndex, int(testNormal.shape[0]))
    malware = allmalware[malIndex, :]
    print(malware.shape)

    testNormal[:, -1] = 0.0
    malware[:, -1] = 1.0
    y_test_malware = np.ones((malware.shape[0], 1))
    y_test_normal = np.zeros((testNormal.shape[0], 1))
    Y_test = np.vstack((y_test_normal, y_test_malware))


    testNormal=testNormal[:,:-1]
    malware=malware[:,:-1]

    # test = np.vstack((testNormal, malware))
    X_test = np.vstack((testNormal, malware))
    print('test:',X_test.shape)
    print('trainNormal:', trainNormal.shape)
    # print('test:', test.shape)
    trainNormal[:, -1] = 0.0

    # X_test = test[:, :-1]
    X_train_normal = trainNormal[:, :-1]
    #
    # X_test.astype(np.float64)
    print('trainNormal:', X_train_normal.shape)

    # X_test = scaler.fit_transform(X_test)

    # Y_test=test[:,-1]
    # Y_test = np.expand_dims(Y_test, axis=1)
    # Y_test.astype(np.float32)
    X_train_normal = X_train_normal.astype(float64)
    X_test = X_test.astype(float64)
    Y_test = Y_test.astype(float64)
    return X_train_normal, X_test, Y_test
    # return X_train_normal,X_train_malware,X_test,y_test

def get_typeofmalware(malware_name):
    """
    要将测试集中不同种类的恶意流量进行分离，并且标准化和归一化处理
    :return:
    """
    training_df = pd.read_csv("./unsw/UNSW_NB15_training-set.csv")
    testing_df = pd.read_csv("./unsw/UNSW_NB15_testing-set.csv")
    training_df = pd.DataFrame(training_df)
    testing_df = pd.DataFrame(testing_df)
    df = pd.concat([training_df, testing_df])
    df = df.drop("attack_cat", axis=1)
    training_df = training_df.drop("attack_cat", axis=1)
    # training_df = training_df.drop("label", axis=1)
    # print(training_df.shape)

    x_test_analysis = testing_df[testing_df['attack_cat']==malware_name]
    x_test_analysis = x_test_analysis.drop("attack_cat",axis = 1)
    # print(x_test_analysis.shape)
    sympolic_columns = ["proto", "service", "state"]
    label_column = "Class"
    for column in df.columns:
        if column in sympolic_columns:
            encode_text(training_df, x_test_analysis, column)
        elif not column == label_column:
            minmax_scale_values(training_df, x_test_analysis, column)

    x_test_analysis = x_test_analysis.drop("label", axis=1)
    x_test_analysis = x_test_analysis.drop("id", axis=1)
    print('x_test_malware:',x_test_analysis.shape)
    # print(x_test_analysis.head)
    # print('training_df:',training_df.shape)
    return x_test_analysis

if __name__ == '__main__':
    # main_process()
    x_test_analysis = get_typeofmalware('Analysis')
    print(x_test_analysis.head)