from basic import basic

class mutator:
    def __init__(self):
        self.m = basic.basic()
        
    def get_random_mutations(self, mutator, maximum=4, mutations=None, start=0, stop=0):
        return self.m.get_random_mutations(mutator, maximum, mutations, start, stop)

    def mutate_seed(self, mutator, data):
        return self.m.mutate_seed(mutator, data)

    def random_merge(self, tid):
        return self.m.random_merge(tid)
