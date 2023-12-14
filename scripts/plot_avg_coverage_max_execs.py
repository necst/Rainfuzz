from matplotlib import pyplot as plt
import sys

n_experiments = len(sys.argv)-2

old_avg_y = []
old_avg_x = []
last_old_avg = 0

max_execs = int(sys.argv[1])

for w in range(2, n_experiments + 2):
    file_path = sys.argv[w]
    i = w - 1
    label = "run_{}".format(i)
        
    file = open(file_path, "r")

    x = []
    y = []
    
    
    new_avg_x = []
    new_avg_y = []
    o = 0

    for line in file.readlines()[1:]:
        s = line.split(",")

        time = int(s[0])//1000
        n_exec = int(s[11])
        edges_found = int(s[12])

        if n_exec > max_execs:
            break

        x.append(n_exec)
        y.append(edges_found)      

        if o >= len(old_avg_x) or old_avg_x[o] > n_exec:
            new_avg_x.append(n_exec)
            new_avg_y.append(((last_old_avg*(i-1))+edges_found)/i)
            if i == 2:
                print(n_exec, ((last_old_avg*(i-1))+edges_found)/i)
        else:
            while o < len(old_avg_x) and n_exec >= old_avg_x[o]:
                last_old_avg = old_avg_y[o]
                new_avg_x.append(old_avg_x[o])
                new_avg_y.append(((last_old_avg*(i-1))+edges_found)/i)
                
                if i == 2:
                    print(old_avg_x[o], ((last_old_avg*(i-1))+edges_found)/i)
                o += 1

    while o < len(old_avg_x):
        last_old_avg = old_avg_y[o]
        new_avg_x.append(old_avg_x[o])
        new_avg_y.append(((last_old_avg*(i-1))+edges_found)/i)
        if i == 2:
            print(old_avg_x[o], ((last_old_avg*(i-1))+edges_found)/i)
        o += 1

    old_avg_y = new_avg_y.copy()
    old_avg_x = new_avg_x.copy()

    plt.plot(x, y, label=label, color="#ffb99c")

plt.plot(new_avg_x, new_avg_y, label="average", color="#000000")

plt.legend()
plt.savefig("./edges_max_exec")
