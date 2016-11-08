""" A Python Class
A simple Python graph class, demonstrating the essential 
facts and functionalities of graphs.
"""

class Graph(object):

    def __init__(self):
        """ initializes a graph object """
        self.__graph_dict = {}
        self.gname = "none"
        self.edge_count = 0
        self.vertex_count = 0
 
    def vertices(self):
        """ returns the vertices of a graph """
        return list(self.__graph_dict.keys())

    def edges(self):
        """ returns the edges of a graph """
        return self.__generate_edges()

    def set_graph_name(self, gname):
        self.gname = gname

    def get_graph_name(self):
        return self.gname
    
    def add_vertex(self, vertex):
        """ If the vertex "vertex" is not in 
            self.__graph_dict, a key "vertex" with an empty
            list as a value is added to the dictionary. 
            Otherwise nothing has to be done. 
        """
        if vertex not in self.__graph_dict:
            self.__graph_dict[vertex] = []
            

    def add_edge(self, vertex1, vertex2):
        """ assumes that edge is of type set, tuple or list; 
            between two vertices can be multiple edges! 
        """
        self.edge_count += 1
        if vertex1 in self.__graph_dict:
            self.__graph_dict[vertex1].append(vertex2)
        else:
            self.__graph_dict[vertex1] = [vertex2]


    def __generate_edges(self):
        """ A static method generating the edges of the 
            graph "graph". Edges are represented as sets 
            with one (a loop back to the vertex) or two 
            vertices 
        """
        edges = []
        for vertex in sorted(self.__graph_dict.keys()):
            for neighbour in self.__graph_dict[vertex]:
                #if [neighbour, vertex] not in edges:
                edges.append([vertex, neighbour])
        return edges
    
    def get_vertex_counts(self): # creates a dict of all the vertices and counts there occurrences.
        vertex_map = {}
        for vertex in sorted(self.__graph_dict):
            if vertex not in vertex_map:
                vertex_map[vertex] = 1
            else:
                vertex_map[vertex] += 1
            nodes = sorted(self.__graph_dict[vertex])
            for node in nodes:
                if node not in vertex_map:
                    vertex_map[node] = 1
                else:
                    vertex_map[node] += 1
                
        return vertex_map     
    
    def __str__(self):
        res = "vertices: "
        for k in self.__graph_dict:
            res += str(k) + " "
        res += "\nedges: "
        for edge in self.__generate_edges():
            res += str(edge) + " "
        return res

    def to_str_graphviz(self):
        res = "digraph \"" + self.gname + "\" {\n"
        for edge in self.__generate_edges():
            res += "\"" + edge[0] + "\" -> \"" + edge[1] + "\";\n"
        res += "}\n"
        return res            
            
    def to_str_graphviz_no_quotes(self):
        counter = 0
        res = "digraph " + self.gname + " {\n"
        for vertex in sorted(self.__graph_dict.keys()):
            neighbours = []
            for neighbour in self.__graph_dict[vertex]: # graphviz does not like node names starting with numeric
                if neighbour.startswith(('0','1','2','3','4','5','6','7','8','9')):
                    neighbours.append("_" + neighbour)
                else:
                    neighbours.append(neighbour)
            if (len(neighbours) == 1):
                tempstr = str(neighbours).replace('[', '{ ').replace(']',' }')
                res += str(vertex) + " -> " + tempstr + "\n"
                counter += 1
            elif (len(neighbours) > 1):
                res += str(vertex) + " -> "
                tempstr = str(neighbours)
                tempstr = tempstr.replace('[', '').replace('\'','').replace(']','').replace(',', ' ; ')
                res += " { " + tempstr + " } \n"
                counter += 1      
        res += " } \n"
        return res
    
    def to_str_multi_line_sorted_no_leaf(self):
        counter = 0
        res = "digraph " + self.gname + "{\n"
        for vertex in sorted(self.__graph_dict.keys()):
            # res += str(counter)
            if (len(self.__graph_dict[vertex]) > 0):
                res += str(vertex) + " -> "
                res += str(self.__graph_dict[vertex])
                res += "\n"
                counter += 1
        res += "\n}\n"
        return res
    
    def to_str_single_line_sorted_no_leaf(self):
        counter = 0
        res = self.gname + " "
        for vertex in sorted(self.__graph_dict.keys()):
            # res += str(counter)
            if (len(self.__graph_dict[vertex]) > 0):
                res += str(vertex) + " -> "
                res += str(self.__graph_dict[vertex]) + " "
                counter += 1
        res += "\n"
        
        return res
    
    def to_str_multi_line_sorted(self):
        counter = 0
        res = "digraph " + self.gname + "{\n"
        for vertex in sorted(self.__graph_dict.keys()):
            # res += str(counter)
            # if (len(self.__graph_dict[vertex]) > 0):
                res += str(vertex) + " -> "
                res += str(self.__graph_dict[vertex])
                res += "\n"
                counter += 1
        res += "\n}\n"
        return res
    
    def to_str_multi_line_no_leaf(self):
        counter = 0
        res = "digraph " + self.gname + "{\n"
        for vertex in self.__graph_dict:
            # res += str(counter)
            if (len(self.__graph_dict[vertex]) > 0):
                res += str(vertex) + " -> "
                res += str(self.__graph_dict[vertex])
                res += "\n"
                counter += 1
        res += "\n}\n"
        return res
    
    def to_str_multi_line(self):
        counter = 0
        res = "digraph " + self.gname + "{\n"
        for vertex in self.__graph_dict:
            # res += str(counter)
            res += str(vertex) + " -> "
            res += str(self.__graph_dict[vertex])
            res += "\n"
            counter += 1
        res += "\n}\n"
        return res
    
    def to_str_single_line_sorted(self):
        counter = 0
        res = "digraph " + self.gname + "{ "
        for vertex in sorted(self.__graph_dict.keys()):
            # res += "(" + str(counter) + ")"
            res += "(" + str(vertex) + ") -> "
            res += str(self.__graph_dict[vertex])
            #res += "\n"
            counter += 1
            
        res += " }\n"
        return res
    
    def to_str(self, str_type):
        if (str_type == 'multi'):
            return self.to_str_multi_line_sorted()
        if (str_type == 'multinoleaf'):
            return self.to_str_multi_line_sorted_no_leaf()
        if (str_type == 'single'):
            return self.to_str_single_line_sorted()
        if (str_type == 'singlenoleaf'):
            return self.to_str_single_line_sorted_no_leaf()
        if (str_type == 'graphviz'):
            return self.to_str_graphviz_no_quotes()
        
        return self.to_string_single_line_sorted()
        
        
    def find_isolated_vertices(self):
        """ returns a list of isolated vertices. """
        graph = self.__graph_dict
        isolated = []
        for vertex in graph:
            print(isolated, vertex)
            if not graph[vertex]:
                isolated += [vertex]
        return isolated

    def find_path(self, start_vertex, end_vertex, path=[]):
        """ find a path from start_vertex to end_vertex 
            in graph """
        graph = self.__graph_dict
        path = path + [start_vertex]
        if start_vertex == end_vertex:
            return path
        if start_vertex not in graph:
            return None
        for vertex in graph[start_vertex]:
            if vertex not in path:
                extended_path = self.find_path(vertex, 
                                               end_vertex, 
                                               path)
                if extended_path: 
                    return extended_path
        return None
    

    def find_all_paths(self, start_vertex, end_vertex, path=[]):
        """ find all paths from start_vertex to 
            end_vertex in graph """
        graph = self.__graph_dict 
        path = path + [start_vertex]
        if start_vertex == end_vertex:
            return [path]
        if start_vertex not in graph:
            return []
        paths = []
        for vertex in graph[start_vertex]:
            if vertex not in path:
                extended_paths = self.find_all_paths(vertex, 
                                                     end_vertex, 
                                                     path)
                for p in extended_paths: 
                    paths.append(p)
        return paths

    def is_connected(self, vertices_encountered = None, start_vertex=None):
        """ determines if the graph is connected """
        if vertices_encountered is None:
            vertices_encountered = set()
        gdict = self.__graph_dict        
        vertices = gdict.keys() 
        if not start_vertex:
            # chosse a vertex from graph as a starting point
            start_vertex = vertices[0]
        vertices_encountered.add(start_vertex)
        if len(vertices_encountered) != len(vertices):
            for vertex in gdict[start_vertex]:
                if vertex not in vertices_encountered:
                    if self.is_connected(vertices_encountered, vertex):
                        return True
        else:
            return True
        return False

    def vertex_degree(self, vertex):
        """ The degree of a vertex is the number of edges connecting
            it, i.e. the number of adjacent vertices. Loops are counted 
            double, i.e. every occurrence of vertex in the list 
            of adjacent vertices. """ 
        adj_vertices =  self.__graph_dict[vertex]
        degree = len(adj_vertices) + adj_vertices.count(vertex)
        return degree

    def degree_sequence(self):
        """ calculates the degree sequence """
        seq = []
        for vertex in self.__graph_dict:
            seq.append(self.vertex_degree(vertex))
        seq.sort(reverse=True)
        return tuple(seq)

    def n_edges(self):
        return self.edge_count
    
    def n_vertices(self):
        # this has to be done when the graph is completed
        # otherwise can get double counting of vertices.
        self.vertex_count = len(self.__graph_dict.keys())
        for vertex in self.__graph_dict:
            nodes = self.__graph_dict[vertex]
            for node in nodes:
                if node not in self.__graph_dict:
                    self.vertex_count += 1
                
        return self.vertex_count
    
    @staticmethod
    def is_degree_sequence(sequence):
        """ Method returns True, if the sequence "sequence" is a 
            degree sequence, i.e. a non-increasing sequence. 
            Otherwise False is returned.
        """
        # check if the sequence sequence is non-increasing:
        return all( x>=y for x, y in zip(sequence, sequence[1:]))
  

    def delta_min(self):
        """ the minimum degree of the vertices """
        min = 100000000
        for vertex in self.__graph_dict:
            vertex_degree = self.vertex_degree(vertex)
            if vertex_degree < min:
                min = vertex_degree
        return min
        
    def delta_max(self):
        """ the maximum degree of the vertices """
        max = 0
        for vertex in self.__graph_dict:
            vertex_degree = self.vertex_degree(vertex)
            if vertex_degree > max:
                max = vertex_degree
        return max

    def density(self):
        """ method to calculate the density of a graph """
        g = self.__graph_dict
        V = len(g.keys())
        E = len(self.edges())
        if (V < 2): # get a divide by zero if only one vertex!
            V = 2
            
        return 2.0 * E / (V *(V - 1))

    def diameter(self):
        """ calculates the diameter of the graph """
        
        v = list(self.__graph_dict.keys()) 
        pairs = [ (v[i],v[j]) for i in range(len(v)-1) for j in range(i+1, len(v))]
        smallest_paths = []
        for (s,e) in pairs:
            paths = self.find_all_paths(s,e)
            if (len(paths) > 0):
                smallest = sorted(paths, key=len)[0]
                smallest_paths.append(smallest)

        smallest_paths.sort(key=len)

        # longest path is at the end of list, 
        # i.e. diameter corresponds to the length of this path
        # DGC: this crashes with out of range index if the graph
        # has diameter = 1 ????
        if (len(smallest_paths) > 0):
            diameter = len(smallest_paths[-1])
        else:
            diameter = 1
            
        return diameter

    @staticmethod
    def erdoes_gallai(dsequence):
        """ Checks if the condition of the Erdoes-Gallai inequality 
            is fullfilled 
        """
        if sum(dsequence) % 2:
            # sum of sequence is odd
            return False
        if Graph.is_degree_sequence(dsequence):
            for k in range(1,len(dsequence) + 1):
                left = sum(dsequence[:k])
                right =  k * (k-1) + sum([min(x,k) for x in dsequence[k:]])
                if left > right:
                    return False
        else:
            # sequence is increasing
            return False
        return True

   


if __name__ == "__main__":

    g = { "a" : ["d"],
          "b" : ["c"],
          "c" : ["b", "c", "d", "e"],
          "d" : ["a", "c"],
          "e" : ["c"],
          "f" : []
        }

    graph = Graph(g)

    print(graph)

    for node in graph.vertices():
        print(graph.vertex_degree(node))

    print("List of isolated vertices:")
    print(graph.find_isolated_vertices())

    print("""A path from "a" to "e":""")
    print(graph.find_path("a", "e"))

    print("""All pathes from "a" to "e":""")
    print(graph.find_all_paths("a", "e"))

    print("The maximum degree of the graph is:")
    print(graph.Delta())

    print("The minimum degree of the graph is:")
    print(graph.delta())

    print("Edges:")
    print(graph.edges())

    print("Degree Sequence: ")
    ds = graph.degree_sequence()
    print(ds)

    fullfilling = [ [2, 2, 2, 2, 1, 1], 
                         [3, 3, 3, 3, 3, 3],
                         [3, 3, 2, 1, 1]
                       ] 
    non_fullfilling = [ [4, 3, 2, 2, 2, 1, 1],
                        [6, 6, 5, 4, 4, 2, 1],
                        [3, 3, 3, 1] ]

    for sequence in fullfilling + non_fullfilling :
        print(sequence, Graph.erdoes_gallai(sequence))

    print("Add vertex 'z':")
    graph.add_vertex("z")
    print(graph)

    print("Add edge ('x','y'): ")
    graph.add_edge(('x', 'y'))
    print(graph)

    print("Add edge ('a','d'): ")
    graph.add_edge(('a', 'd'))
    print(graph)

