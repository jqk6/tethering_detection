/**************************************************
 * Author: Yi-Chao Chen
 * 2013/07/16 @ Narus
 *
 * Calculate the boot time using TCP Timestamp option and use Weka X-Means for clustering
 *
 * - input:
 *     ./output/
 *        file.group.txt:
 *        The boot time of all IPs
 *        <normalized tcp timestamp>
 *
 * - output
 *     a) ./output/
 *        file.<ip>.offset.txt:
 *        <tx_time> <rx_time> <rx_time_from_1st_pkt> <tx_clock_from_1st_pkt> <tx_time_from_1st_pkt> <offset>
 *     b) ./figures
 *
 * - internal variables
 *     a) PLOT_EPS : output eps or png figure
 *     c) gnuplot  : modify to choose which IPs to plot
 *
 *  e.g. java group_by_tcp_timestamp ./output/2013.07.08.ut.4machines.pcap.txt.group.txt
**************************************************/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;

import weka.core.Attribute;
import weka.core.FastVector;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ConverterUtils.DataSource;
import weka.clusterers.XMeans;
import weka.clusterers.DBSCAN;

public class group_by_tcp_timestamp 
{
    /************************
     * Variables
    *************************/
    /* DEBUG */
    private static boolean DEBUG0 = true;
    private static boolean DEBUG1 = false;
    private static boolean DEBUG2 = true;

    /* Constant */
    // private 


    /************************
     * main function
    *************************/
    public static void main(String[] args) throws Exception {

        /************************
         * Local variables
        *************************/
        String filename;
        boot_time_data boot_times = new boot_time_data();
        XMeans cluster_method;
        DBSCAN cluster_method2;
        

        // Check # of input
        if (args.length == 0) {
            System.err.println("\nUsage: java group_by_tcp_timestamp filename target_ip\n");
            System.exit(1);
        }
        filename  = args[0];
        

        // Read input file
        if(DEBUG2) {
            System.out.println("input file name: " + filename);
            System.out.println();
        }
        
        BufferedReader buf = new BufferedReader(new FileReader(filename));
        String line = null;
        while((line = buf.readLine()) != null) {
            String[] row = line.split(", ");
            double this_boot_time = Double.valueOf(row[0]).doubleValue();
            boot_times.add_val(this_boot_time);

            if(DEBUG1) {
                System.out.println(this_boot_time);
            }
        }


        // Initial and run clustering method
        cluster_method = new XMeans();
        cluster_method.setMaxNumClusters(20);
        cluster_method.setMinNumClusters(1);
        cluster_method.setMaxKMeans(1000000);
        cluster_method.setMaxIterations(1000000000);
        cluster_method.setMaxKMeansForChildren(1000000000);
        cluster_method.setUseKDTree(false);
        cluster_method.buildClusterer(boot_times.data);

        // Analyze clustering results
        System.out.println("Data set name: " + boot_times.data.relationName());
        System.out.println("Number of attributes: " + boot_times.data.numAttributes());
        System.out.println("Number of instances: " + boot_times.data.numInstances());
        // System.out.println("Number of clusters: " + boot_times.data.numberOfClusters());
        
        System.out.println("\nCluster examples:");
        Enumeration enumerated_instances = boot_times.data.enumerateInstances();
        int pre_cluster_num = -1;
        while(enumerated_instances.hasMoreElements()) {
            Instance inst = (Instance)enumerated_instances.nextElement();
            int cluster_num = cluster_method.clusterInstance(inst);

            if(pre_cluster_num != cluster_num) {
                System.out.println("boot time=" + inst.value(0) + " at cluster: " + cluster_num);
                pre_cluster_num = cluster_num;
            }
        }

        // Centers
        System.out.println("\nCenters");
        Instances centers = cluster_method.getClusterCenters();
        Enumeration enumerated_centers = centers.enumerateInstances();
        int cluster_ind = 0;
        while(enumerated_centers.hasMoreElements()) {
            Instance inst = (Instance)enumerated_centers.nextElement();
            System.out.print("center " + cluster_ind + ": ");
            for(int att_ind = 0; att_ind < centers.numAttributes(); att_ind ++) {
                System.out.print(inst.value(att_ind) + ", ");
            }
            System.out.println();
            cluster_ind ++;
        }

        /////////////////////////////////////////////////////////////

        System.out.println("\nDBscan: ");

        cluster_method2 = new DBSCAN();
        cluster_method2.setEpsilon(1000);
        cluster_method2.setMinPoints(1);
        // cluster_method2.setDatabase_Type("weka.clusterers.forOPTICSAndDBScan.Databases.SequentialDatabase");
        // cluster_method2.setDatabase_distanceType("weka.clusterers.forOPTICSAndDBScan.DataObjects.EuclidieanDataObject");
        cluster_method2.buildClusterer(boot_times.data);

        // Analyze clustering results
        System.out.println("Data set name: " + boot_times.data.relationName());
        System.out.println("Number of attributes: " + boot_times.data.numAttributes());
        System.out.println("Number of instances: " + boot_times.data.numInstances());
        // System.out.println("Number of clusters: " + boot_times.data.numberOfClusters());
        System.out.println("Distance type: " + cluster_method2.getDatabase_distanceType() );
        System.out.println("Database type: " + cluster_method2.getDatabase_Type() );
        System.out.println("Cluster: " + cluster_method2.toString() );
        

        System.out.println("\nCluster examples:");
        enumerated_instances = boot_times.data.enumerateInstances();
        pre_cluster_num = -1;
        while(enumerated_instances.hasMoreElements()) {
            Instance inst = (Instance)enumerated_instances.nextElement();
            int cluster_num = cluster_method2.clusterInstance(inst);

            if(pre_cluster_num != cluster_num) {
                System.out.println("boot time=" + inst.value(0) + " at cluster: " + cluster_num);
                pre_cluster_num = cluster_num;
            }
        }

        // Centers
        // System.out.println("\nCenters");
        // centers = cluster_method2.getClusterCenters();
        // Enumeration enumerated_centers = centers.enumerateInstances();
        // int cluster_ind = 0;
        // while(enumerated_centers.hasMoreElements()) {
        //     Instance inst = (Instance)enumerated_centers.nextElement();
        //     System.out.print("center " + cluster_ind + ": ");
        //     for(int att_ind = 0; att_ind < centers.numAttributes(); att_ind ++) {
        //         System.out.print(inst.value(att_ind) + ", ");
        //     }
        //     System.out.println();
        //     cluster_ind ++;
        // }


        
    }   /* end main */

}


/**************************************************
 * the class used to store data
**************************************************/
class boot_time_data
{
    Instances data;

    boot_time_data() {
        // only have one attribute: boot time
        FastVector atts = new FastVector();
        atts.addElement(new Attribute("boot time"));

        this.data = new Instances("MyData", atts, 0);


        // System.out.println("Initial data complete");
    }

    void add_val(double boot_time) {
        // System.out.println("add value to data: " + boot_time);


        double[] vals = new double[this.data.numAttributes()];
        vals[0] = boot_time;

        data.add(new Instance(1.0, vals));
    }
}
