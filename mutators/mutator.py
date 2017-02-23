from copy import deepcopy
from random import getrandbits, randrange, choice, shuffle

from basic import basic

class mutator:
    def __init__(self):
        self.random_merge_cache = {}
        self.m = basic()
        
    def random_mutation(self, mutator, maximum=4, mutations=None, start=0, stop=0):
        return self.m.random_mutation(mutator, maximum, mutations, start, stop)

    def mutate_seed(self, mutator, data):
        return self.m.mutate_seed(mutator, data)

    def random_merge(self, testcases, tid):
        #if tid == 0: return None
        mutated = deepcopy(testcases[tid])

        def get_mutations(parent_id, mutations=[]):
            for tid in testcases[parent_id]["childs"]:
                if tid >= len(testcases):
                    continue
                t  = testcases[tid]
                if t["parent_id"] == parent_id and t["id"] != parent_id:
                    for m in ["mutations"]:
                        if m not in mutations:
                            mutations += [m]
                    mutations = get_mutations(tid, mutations)
            return mutations

        if tid not in self.random_merge_cache:
            self.random_merge_cache[tid] = get_mutations(tid)

        mutations = self.random_merge_cache[tid]
        if len(mutations) == 0:
            return None

        shuffle(mutations)
        mutated["mutations"] += mutations[:randrange(min(10,len(mutations)))]
        mutated["description"] = "random-merge %d" % (tid)
        mutated["parent_id"] = tid
        
        return mutated

    def initial_testcase(self):
        initial_testcase = {}
        initial_testcase["id"] = 0
        initial_testcase["parent_id"] = 0
        initial_testcase["len"] = 0
        initial_testcase["mutations"] = []
        initial_testcase["description"] = ""
        initial_testcase["childs"] = []

        return initial_testcase
