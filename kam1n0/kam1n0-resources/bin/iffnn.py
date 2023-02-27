import torch
import torch.nn as nn 
from collections import OrderedDict
import json
import numpy as np
import argparse
import os



class IFFNN_MulCls(nn.Module):
    def __init__(self, input_size, hidden_sizes, num_classes,use_last_param=True,use_dropout=False, act_func = 'relu'):
        super(IFFNN_MulCls, self).__init__()
        self.input_size = input_size
        self.num_classes = num_classes
        self.use_last_param = use_last_param
        dic = OrderedDict()
        previous_dim = input_size
        for i,dim in enumerate(hidden_sizes):
            lay = nn.Linear(previous_dim,dim)
            previous_dim = dim
            dic['linear'+str(i)]=lay
            if act_func == 'tanh':
                dic['act_func'+str(i)]=nn.Tanh()
            else:
                assert(act_func == 'relu')
                dic['act_func'+str(i)]=nn.ReLU()
                
        n_hid = len(hidden_sizes)        
        lay = nn.Linear(previous_dim,input_size*num_classes)
        dic['linear'+str(n_hid)]=lay
        self.iffnnpart1 = nn.Sequential(dic)
        
        
        self.last_weight = torch.nn.Parameter(torch.rand([input_size*num_classes]))
        self.register_parameter(name='weight', param=self.last_weight)
        self.last_bias = torch.nn.Parameter(torch.zeros([num_classes]))
        self.register_parameter(name='bias', param=self.last_bias)
        self.softmax = nn.Softmax(dim=1)
        
        
    def forward(self, x, with_explain = True):
        out = self.iffnnpart1(x)
        if self.use_last_param:
            out = out*self.last_weight
        full_features = x.repeat(1,self.num_classes)
        out = full_features*out
        out = out.reshape(-1,self.num_classes,self.input_size)
        weights = out
        out = out.sum(axis=2)
        if self.use_last_param:
            out = out + self.last_bias
        _,classes = torch.max(out.data, 1)
        if with_explain:
            out = self.softmax(out)
            pred_results = []
            for pre in list(out.detach().numpy()):
                pred_results.append(list(pre))
            exp_results = []
            for i in range(len(x)):
                current = []
                weight = weights[i][classes[i]].detach().numpy()#.cpu().detach().numpy()
                exp_results.append(weight)
            return pred_results,exp_results 
        else:
            return out
    def explain(self, x):
        out = self.iffnnpart1(x)
        if self.use_last_param:
            out = out*self.last_weight
        full_features = x.repeat(1,self.num_classes)
        out = full_features*out
        out = out.reshape(-1,self.num_classes,self.input_size)
        
        results = []
        for i in range(len(x)):
            current = []
            sam = x[i].cpu().detach().numpy()
            current.append(sam)
            for j in range(self.num_classes):
                weight = out[i][j].cpu().detach().numpy()
                current.append(weight)
            results.append(current)
            #results.append((sam,weight,y[i].cpu().detach().numpy()))
        
        return results
        
def train(hyper_f,train_f,save_path):
    path = os.path.dirname(save_path)
    log_f = open(os.path.join(path,'log.txt'),'w')
    log_f.write("begin training\n")

    with open(hyper_f) as f:
        hyps = json.load(f)
    hid_dims = []
    for dim in hyps['hiddendims'].split(','):
        if not dim == '':
            hid_dims.append(int(dim))
    model = IFFNN_MulCls(int(hyps['feature_length']),hid_dims,int(hyps['n_class']))
    num_epochs = int(hyps['n_epoch'])
    learning_rate = float(hyps['learning_rate'])
    batch_size = int(hyps['batch_size'])
    log_f.write("hypers:"+str(hyps)+"\n")
    
    f = open(train_f,'r')
    lines = f.readlines()
    f.close()
    log_f.write("trainning data loaded\n")
    lines = [line.strip() for line in lines]
    train_x = []
    train_y = []
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate) 
    for line in lines:
        line = line.split(',')
        train_y.append(int(line[0]))
        train_x.append([float(dig) for dig in line[1:]])
    for epoch in range(num_epochs):
        n_samples = 0
        n_correct = 0
        
        x_loader = torch.utils.data.DataLoader(torch.tensor(train_x,dtype=torch.float32),
                                          batch_size=batch_size,
                                          shuffle=False)
        y_loader = torch.utils.data.DataLoader(torch.tensor(train_y,dtype=torch.long),
                                          batch_size=batch_size,
                                          shuffle=False)
        for x,y in zip(x_loader,y_loader):
            labels=y
            outputs = model(x,False)
            loss = criterion(outputs, labels)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step() 
            _,predicted = torch.max(outputs.data, 1)
            n_samples += labels.size(0)
            n_correct += (predicted == labels).sum().item() 
        acc = 100.0 * n_correct / n_samples
        print (f'Epoch [{epoch+1}/{num_epochs}], Loss: {loss.item():.4f} Acc: {acc} %') 

    torch.save({
    'model_state_dict': model.state_dict()
    }, save_path)
    log_f.write("trained\n")
    log_f.close()
        
def test(hyper_f,test_f,save_path,target_path):
    path = os.path.dirname(save_path)
    log_f = open(os.path.join(path,'log.txt'),'w')
    log_f.write("begin predicting\n")

    with open(hyper_f) as f:
        hyps = json.load(f)
    hid_dims = []
    for dim in hyps['hiddendims'].split(','):
        if not dim == '':
            hid_dims.append(int(dim))
    model = IFFNN_MulCls(int(hyps['feature_length']),hid_dims,int(hyps['n_class']))
    checkpoint = torch.load(save_path)
    model.load_state_dict(checkpoint['model_state_dict'])
    batch_size = int(hyps['batch_size'])
    log_f.write("hypers:"+str(hyps)+"\n")
    
    f = open(test_f,'r')
    lines = f.readlines()
    f.close()
    log_f.write("predicting data loaded\n")
    lines = [line.strip() for line in lines]
    test_x = []
    for line in lines:
        line = line.split(',')
        test_x.append([float(dig) for dig in line])
        
    x_loader = torch.utils.data.DataLoader(torch.tensor(test_x,dtype=torch.float32),
                                      batch_size=batch_size,
                                      shuffle=False)
    results = []
    explains = []
    for x in x_loader:
        outputs,explanation = model(x,True)
        #_,predicted = torch.max(outputs.data, 1)
        results.extend(outputs)
        explains.extend(explanation)
        
    f = open(target_path+'_result.csv','w')
    for res in results:
        for i,cls_prob in enumerate(res):
            if i == 0:
                f.write(str(cls_prob))
            else:
                f.write(","+str(cls_prob))
        f.write("\n")
    f.close()
    
    f = open(target_path+'_interpret.csv','w')
    for exp in explains:
        for i,weight in enumerate(exp):
            if i == 0:
                f.write(str(weight))
            else:
                f.write(","+str(weight))
        f.write("\n")
    f.close()
    log_f.write("predicted\n")
    log_f.close()
        
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--hyper', type=str, required=True, help='the json file path of hyperparameter')
    parser.add_argument('--task', type=str, required=True, help='the task to run, train or predict')
    parser.add_argument('--train', type=str, default='train.csv', help='the train file path')
    parser.add_argument('--test', type=str, default='test.csv', help='the test file path')
    parser.add_argument('--save', type=str, required=True, help='the file path to save the trained model')
    parser.add_argument('--target_path', type=str, default='./11036980', help='the path to the result file')
    args = parser.parse_args()
    path = os.path.dirname(args.save)
    if args.task == 'train':
        train(args.hyper,args.train,args.save)
    else:
        assert(args.task == 'predict')
        test(args.hyper,args.test,args.save,args.target_path)