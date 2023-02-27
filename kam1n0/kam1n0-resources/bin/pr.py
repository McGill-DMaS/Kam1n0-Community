import argparse
import os
import numpy as np
from tqdm import tqdm
from joblib import Parallel, delayed
from sklearn.cluster import KMeans
import numpy as np
import sys

def get_func_call(fcallpath):
    f = open(fcallpath,'r')
    lines = f.readlines()
    lines = [line.strip() for line in lines]
    f.close()
    all_func_call = {}
    for line in lines:
        if ':' in line:
            bin_id = line[:-1]
            called_lis = []
        elif ';' in line:
            if len(called_lis) > 0:
                if bin_id not in all_func_call:
                    all_func_call[bin_id] = {}
                #if len(all_func_call[bin_id]) < 100:##
                #    all_func_call[bin_id][func_id] = called_lis[:100]##
                all_func_call[bin_id][func_id] = called_lis  #############
            func_id = line[:-1]
            called_lis = []
        else:
            called_lis.append(line)
    return all_func_call

def get_func_cluster(fcallpath):
    f = open(funcclusterpath,'r')
    lines = f.readlines()
    lines = [line.strip() for line in lines]
    f.close()
    func_cluster = {}
    n_clusters = 0
    for line in lines:
        if ':' in line:
            cluster = line[:-1]
            n_clusters += 1 
        else:
            func_id = line
            func_cluster[func_id] = cluster
    print("number of clusters:",n_clusters)
    print("number of functions:",len(func_cluster))
    return func_cluster

def min_dist_of_an_executable(func_call):
    func_map = {}
    rev_func_map = {}
    i = 0
    for k,v in func_call.items():
        if k not in func_map:
            func_map[k] = i
            rev_func_map[i]=k
            i += 1
        for fun in v:
            if fun not in func_map:
                func_map[fun] = i
                rev_func_map[i]=fun
                i += 1
    n_func = len(func_map)
    dists = np.ones((n_func,n_func))*999999
    for i in range(n_func):
        dists[i][i] = 0
    for k,v in func_call.items():
        for fun in v:
            dists[func_map[k]][func_map[fun]] = 1
            dists[func_map[fun]][func_map[k]] = 1
    for k in range(n_func):
        for i in range(n_func):
            for j in range(n_func):
                tmp = dists[i][k] + dists[k][j]
                if dists[i][j] > tmp:
                    dists[i][j] = tmp
                    dists[j][i] = tmp
    return (dists, func_map, rev_func_map)


def get_fis(all_func_call,func_cluster,root_path,name,threshold = 30):
    call_graph = {}
    d_call_graph = {}
    for func_call in all_func_call.values():
        for caller, callees in func_call.items():
            if not caller in func_cluster:
                continue
            caller_cls = func_cluster[caller]
            for callee in callees:
                if callee in func_cluster:
                    callee_cls = func_cluster[callee]
                    if caller_cls not in call_graph:
                        call_graph[caller_cls] = {}
                    if callee_cls not in call_graph[caller_cls]:
                        call_graph[caller_cls][callee_cls] = 0
                    call_graph[caller_cls][callee_cls] += 1
                    
                    if callee_cls not in call_graph:
                        call_graph[callee_cls] = {}
                    if caller_cls not in call_graph[callee_cls]:
                        call_graph[callee_cls][caller_cls] = 0
                    call_graph[callee_cls][caller_cls] += 1
                    
                    if caller_cls not in d_call_graph:
                        d_call_graph[caller_cls] = {}
                    if callee_cls not in d_call_graph[caller_cls]:
                        d_call_graph[caller_cls][callee_cls] = 0
                    d_call_graph[caller_cls][callee_cls] += 1
                    
                    
    for caller, callees in call_graph.items():       
        to_remove = []
        for callee in callees:
            if call_graph[caller][callee] < threshold:
                to_remove.append(callee)
        for callee in to_remove:
            callees.pop(callee)
    print(len(call_graph),'clusters included')
    patterns = []
    while len(call_graph) > 0:
        selected = set()
        clu = list(call_graph.keys())[0]
        selected.add(clu)
        add_cluster(clu, call_graph, selected)
        if len(selected) > 1:
            patterns.append(selected)
        for clu in selected:
            call_graph.pop(clu)
    
    print('final',len(patterns),'patterns')
    
    f = open(os.path.join(root_path,name)+'_patterns.txt','w')
    for i,pattern in enumerate(patterns):
        f.write("pattern_"+str(i)+":\n")
        for it in pattern:
            f.write(it+"\n")
    f.close()
    
    f = open(os.path.join(root_path,name)+'_cluster_calls.txt','w')
    for caller, callees in d_call_graph.items():
        for callee,count in callees.items():
            f.write(caller+" "+callee+" "+str(count)+"\n")
    f.close()
    
    return patterns
        
def add_cluster(target, call_graph, selected):
    for clu in call_graph[target]:
        if clu in selected:
            continue
        selected.add(clu)
        add_cluster(clu, call_graph, selected)
    
def get_cluster_map(all_func_call,func_cluster,root_path,name,n_patterns):
    cluster_dist = {}
    #for func_call in tqdm(all_func_call.values()):
    #    dists, func_map, rev_func_map = min_dist_of_an_executable(func_call)
    n_jobs=2
    print("begin Floyd")
    with Parallel(n_jobs=n_jobs, verbose=10) as parallel:
        dist_results = parallel(
            delayed(min_dist_of_an_executable)(func_call) for
            func_call in
            all_func_call.values())
        
    for dists_ in dist_results:
        dists, func_map, rev_func_map = dists_
        for i in range(len(dists)):
            if rev_func_map[i] in func_cluster:
                for j in range(i+1,len(dists)):
                    if rev_func_map[j] in func_cluster:
                        cluster_i = func_cluster[rev_func_map[i]]
                        cluster_j = func_cluster[rev_func_map[j]]
                        if cluster_i not in cluster_dist:
                            cluster_dist[cluster_i] = {}
                        if cluster_j not in cluster_dist[cluster_i]:
                            cluster_dist[cluster_i][cluster_j] = 0.
                        cluster_dist[cluster_i][cluster_j] += 1/dists[i][j]
        
                        if cluster_j not in cluster_dist:
                            cluster_dist[cluster_j] = {}
                        if cluster_i not in cluster_dist[cluster_j]:
                            cluster_dist[cluster_j][cluster_i] = 0.
                        cluster_dist[cluster_j][cluster_i] += 1/dists[j][i]
    
    print("begin cluster indexing")
    i = 0
    cluster_ind = {}
    rev_cluster_ind = {}
    for clu in cluster_dist:
        cluster_ind[clu] = i
        rev_cluster_ind[i] = clu
        i += 1
    
    n_clu = len(cluster_ind)
    print("n clusters:",n_clu)
    dis_matrix = np.zeros((n_clu,n_clu))
    for k,vs in cluster_dist.items():
        k_clu_ind = cluster_ind[k]
        for v in vs:
            v_clu_ind = cluster_ind[v]
            if k == v:
                continue
            dis_matrix[k_clu_ind][v_clu_ind] = vs[v]
            dis_matrix[v_clu_ind][k_clu_ind] = vs[v]
        
    diag = np.diag(dis_matrix.sum(axis=1))

    L = diag-dis_matrix
    
    eig_vals, eig_vecs = np.linalg.eigh(L)
    sorted_val_inds = np.argsort(eig_vals)
    eig_vecs = eig_vecs[:,sorted_val_inds]
    eig_vals = eig_vals[sorted_val_inds]
    
    #n_patterns = 0
    #for val in eig_vals:
    #    if val > 1e-15:
    #        if val<10:
    #            n_patterns += 1
    #        else:
    #            break
    print("n patterns:",n_patterns)


    for i,val in enumerate(eig_vals):
        if val > 1e-15:
            first_non_zero = i
            break
    
    clustering = KMeans(n_patterns)
    clustering.fit(eig_vecs[:,first_non_zero:n_patterns+first_non_zero])
    labels = clustering.labels_
    pattern_clusters = {}
    for i,lab in enumerate(labels):
        if lab not in pattern_clusters:
            pattern_clusters[lab] = []
        pattern_clusters[lab].append(rev_cluster_ind[i])
        
    f = open(os.path.join(root_path,name)+'_patterns.txt','w')
    j = 1
    for i,clusters in pattern_clusters.items():
        if len(clusters) ==1:
            continue
        f.write("pattern_"+str(j)+":\n")
        j+=1
        for it in clusters:
            f.write(it+"\n")
    f.close()



    call_graph = {}
    d_call_graph = {}
    for func_call in all_func_call.values():
        for caller, callees in func_call.items():
            if not caller in func_cluster:
                continue
            caller_cls = func_cluster[caller]
            for callee in callees:
                if callee in func_cluster:
                    callee_cls = func_cluster[callee]
                    if caller_cls not in call_graph:
                        call_graph[caller_cls] = {}
                    if callee_cls not in call_graph[caller_cls]:
                        call_graph[caller_cls][callee_cls] = 0
                    call_graph[caller_cls][callee_cls] += 1

                    if callee_cls not in call_graph:
                        call_graph[callee_cls] = {}
                    if caller_cls not in call_graph[callee_cls]:
                        call_graph[callee_cls][caller_cls] = 0
                    call_graph[callee_cls][caller_cls] += 1

                    if caller_cls not in d_call_graph:
                        d_call_graph[caller_cls] = {}
                    if callee_cls not in d_call_graph[caller_cls]:
                        d_call_graph[caller_cls][callee_cls] = 0
                    d_call_graph[caller_cls][callee_cls] += 1

    f = open(os.path.join(root_path,name)+'_cluster_calls.txt','w')
    for caller, callees in d_call_graph.items():
        for callee,count in callees.items():
            f.write(caller+" "+callee+" "+str(count)+"\n")
    f.close()
    
    return pattern_clusters
    
    
if __name__ == '__main__':
    sys.setrecursionlimit(9999999)
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--root', type=str, required=True, help='the file path to save the trained model')
    parser.add_argument('--name', type=str, required=True, help='the path to the result file')
    parser.add_argument('--method', type=str, default="fis", help='the method to recognize patterns')
    parser.add_argument('--nsup', type=int, default=10, help='minimal number of support for each pattern')
    parser.add_argument('--npat', type=int, default=1000, help='number of patterns to expect')
    args = parser.parse_args()
    root_path = args.root
    name = args.name
    fcallpath = os.path.join(root_path,name)
    funcclusterpath = os.path.join(root_path,'clusterfuncs.json')

    f = open(os.path.join(root_path,name)+'_log.txt','w')
    
    all_func_call = get_func_call(fcallpath)
    func_cluster = get_func_cluster(funcclusterpath)
    if args.method == 'fis':
        f.write("args.method:"+args.method+'\n')
        patterns = get_fis(all_func_call,func_cluster,root_path,name,threshold = args.nsup)
        f.write("args.nsup:"+str(args.nsup)+'\n')
    else:
        patterns = get_cluster_map(all_func_call,func_cluster,root_path,name,args.npat)
        f.write("args.method:"+args.method+'\n')
        f.write("args.npat:"+str(args.npat)+'\n')

    f.write(fcallpath+" "+name+" "+root_path+'\n')
    f.close()
