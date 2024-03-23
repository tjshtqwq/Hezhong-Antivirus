import os
from tensorflow.keras.preprocessing.sequence import pad_sequences


def preprocess(fn, max_len, datas):


    doc = bytearray(datas)

    seq = pad_sequences([doc], maxlen=max_len, padding='post', truncating='post')
    len_list = [len(doc)]

    return seq[0], len_list[0]



