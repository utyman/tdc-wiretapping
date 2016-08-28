import math
from clint.textui import colored, puts

# returns entropy
def entropy(symbol_dict, totalEvents):
    acc = 0.0
    for key in symbol_dict:
        acc += getFrequency(symbol_dict[key], totalEvents) * getInformation(symbol_dict[key], totalEvents) 
    puts(colored.green("H: " + str(acc)))
    puts(colored.green("Packets occurrences:"))
    puts(colored.green(str(symbol_dict))) 
    
# returns information rendered by a symbol from a source
def getInformation(symbolEvents, totalEvents):
    return -1.0 * math.log(getFrequency(symbolEvents, totalEvents), 2)

# returns frequency of a symbol from a source 
def getFrequency(symbolEvents, totalEvents):
    return float(symbolEvents)/totalEvents