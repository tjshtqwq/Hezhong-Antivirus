from keras.models import load_model

a = load_model('hzml.h5')
print(a.summary())
