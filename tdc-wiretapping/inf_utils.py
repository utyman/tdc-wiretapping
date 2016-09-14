import math
from clint.textui import colored, puts
from os import system, remove
from graphviz import Digraph

def dump_results(symbol_dict, entropy, max_entropy, totalEvents):
    file = open('data.dat', 'w+')
    max = 0.0
    for key in sorted(symbol_dict, key=symbol_dict.__getitem__, reverse=True):
        file.write(str(i) + "\t" + str(key) + "\t \t" + str(information(symbol_dict.get(key), totalEvents)) + "\n")
        if information(symbol_dict.get(key), totalEvents) > max:
            max = information(symbol_dict.get(key), totalEvents)
        i+=1
        
    max = max*1.25
    file.close();
    system('gnuplot -e "max=' + str(max) +'" -e "maxentropy=' + str(max_entropy) + '" -e "entropy=' + str(entropy) + '" plot.gp')
    remove("data.dat")

def dump_graph(symbol_nodos):
    dot = Digraph(comment='Nodos en la red')
    
    for nod in symbol_nodos.keys():
        dot.node(key, key);
    
    for nod in symbol_nodos.keys():
        destinos = symbol_nodos.get(nod);
        for dest in destinos:
            dot.edge(nod, dest, constraint='false');
    
    return dot;
    
    
# returns information
def information(totalSymbol, totalEvents):
    return (-1)*math.log(totalSymbol/totalEvents, 2);

# returns entropy
def entropy(symbol_dict, totalEvents):
    acc = 0.0
    for key in symbol_dict:
        acc += getFrequency(symbol_dict[key], totalEvents) * getInformation(symbol_dict[key], totalEvents)
    return str(acc) 

# max entropy    
def max_entropy(symbol_dict):
    return str(math.log(len(symbol_dict.keys()), 2))
    
# returns information rendered by a symbol from a source
def getInformation(symbolEvents, totalEvents):
    return -1.0 * math.log(getFrequency(symbolEvents, totalEvents), 2)

# returns frequency of a symbol from a source 
def getFrequency(symbolEvents, totalEvents):
    return float(symbolEvents)/totalEvents