def entropy( data ):

    from collections import Counter
    import math
    
    if not data:
        return 0
    
    counter = Counter( data )
    entropy = 0
    
    for count in counter.values():
        p = count / len( data )
        entropy -= p * math.log2( p )
    
    return entropy