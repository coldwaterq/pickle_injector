import torch
import numpy as np

# a secure save function to replace the torch.load
def sec_save_state(model, f):
	state = model.state_dict()
	sec_save(state,f)

def sec_save(data, f):
	# this is the function called by savez, but it allows setting
	# allow_pickle to False
	np.lib.npyio._savez(f, [], data, True, allow_pickle=False)

# a secure load function to replace torch.load
def sec_load(f):
	return np.load(f, allow_pickle=False)

def sec_load_state(model, f):
	data = sec_load(f)
	newSate = {}
	for key in data.keys():
		# convert each array back into a tensor
		newSate[key] = torch.tensor(data[key])
	# enforce strict, so that every key MUST be set
	model.load_state_dict(newSate, strict=True)

if __name__=='__main__':
	modelLoc, modelName = ('pytorch/vision:v0.10.0', 'resnet152')
	# a model with weights set and print the first weights
	model = torch.hub.load(modelLoc, modelName, pretrained=True)
	realState = model.state_dict()
	# save the model
	f = open("out.save",'wb')
	sec_save_state(model, f)
	f.close()
	# the same model but with random weights and print 
	# the first weights to verify different
	model = torch.hub.load(modelLoc, modelName, pretrained=False)
	tempStateDict = model.state_dict()
	different = False
	for k in tempStateDict.keys():
		different = different or not torch.equal(tempStateDict[k],realState[k])
	assert different
	# load the model
	f = open("out.save",'rb')
	sec_load_state(model, f)
	# print the first weights to verify they loaded correctly
	tempStateDict = model.state_dict()
	for k in tempStateDict.keys():
		assert torch.equal(tempStateDict[k],realState[k])
	print('worked')
