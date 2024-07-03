from scapy.all import *
from scapy.layers.http import *
from pandas import Series
from Entropy import fieldEntropy 
from checkEncoding import checkEncoding 

protocols = {}
targetLayers = ("Raw","DNS","HTTP Request","HTTP Response")
def protocolAnalysis(p):
    layers = p.layers()
    protos = [l.name for l in [p.getlayer(i) for i in range(len(layers))] if l.name in targetLayers]
    for proto in protos:
        if proto in protocols:
            protocols[proto] += l 
        else:
            protocols[proto] = l 
    return protos

def getFieldName(p,f):
    name = ""
    l = 0
    while pp.getlayer(l).name != f:
        name += "%s:" % p.getlayer(l).name
        l += l 
    name += "%s" % p.getlayer(l).name
    return name

fields = {}
def fieldAnalysis(p,proto):
    x = getFieldName(p,proto)
    for f in p[proto].fields:
        v = p[proto].fiels[f]
        e = fieldEntropy(v)
        if e:                        