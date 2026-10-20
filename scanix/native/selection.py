"""Stable target-major pair IDs; byte-bounded selection, shared with protocol 3."""
class Selection:
    def __init__(self, total, index=0, count=1, completed=None):
        if (type(total) is not int or not 0 <= total <= 1_000_000 or
            type(count) is not int or not 1 <= count <= 1024 or
            type(index) is not int or not 0 <= index < count):
            raise ValueError('invalid work selection')
        self.total,self.index,self.count=total,index,count
        self.completed=bytearray(total) if completed is None else bytearray(completed)
        if len(self.completed)!=total or any(value not in (0,1) or value and id % count!=index
                                              for id,value in enumerate(self.completed)):
            raise ValueError('invalid completed work selection')

    def in_shard(self, id):
        return type(id) is int and 0 <= id < self.total and id % self.count==self.index

    def selected(self, id):
        return self.in_shard(id) and not self.completed[id]

    @property
    def requested(self):
        return len(range(self.index,self.total,self.count))

    @property
    def remaining(self):
        return self.requested - self.done

    @property
    def done(self):
        return sum(self.completed)
