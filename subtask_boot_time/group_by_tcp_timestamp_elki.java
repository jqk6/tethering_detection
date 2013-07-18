/**************************************************
 * Author: Yi-Chao Chen
 * 2013/07/16 @ Narus
 *
 * Calculate the boot time using TCP Timestamp option and use Weka X-Means for clustering (using ELKI library)
 *
 * - input:
 *     ./output/
 *        file.group.txt:
 *        The boot time of all IPs
 *        <normalized tcp timestamp>
 *
 * - output
 *     ./output/
 *     input_file.dbscan_cluster
 *     <Cluster i> <estimated boot time>
 *
 * - internal variables
 *
 *  e.g. java group_by_tcp_timestamp_elki ./output/2013.07.08.ut.4machines.pcap.txt.group.txt
**************************************************/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;

import de.lmu.ifi.dbs.elki.algorithm.clustering.DBSCAN;
import de.lmu.ifi.dbs.elki.algorithm.clustering.DBSCAN.Parameterizer;
import de.lmu.ifi.dbs.elki.distance.distancevalue.DoubleDistance;
import de.lmu.ifi.dbs.elki.distance.distancefunction.EuclideanDistanceFunction;
import de.lmu.ifi.dbs.elki.utilities.ClassGenericsUtil;
import de.lmu.ifi.dbs.elki.utilities.optionhandling.parameterization.ListParameterization;
import de.lmu.ifi.dbs.elki.data.NumberVector;
import de.lmu.ifi.dbs.elki.data.VectorUtil;
import de.lmu.ifi.dbs.elki.data.VectorUtil.SortDBIDsBySingleDimension;
import de.lmu.ifi.dbs.elki.data.type.TypeUtil;
import de.lmu.ifi.dbs.elki.data.Cluster;
import de.lmu.ifi.dbs.elki.data.Clustering;
import de.lmu.ifi.dbs.elki.data.model.Model;
import de.lmu.ifi.dbs.elki.database.Database;
import de.lmu.ifi.dbs.elki.database.StaticArrayDatabase;
import de.lmu.ifi.dbs.elki.database.ids.ArrayModifiableDBIDs;
import de.lmu.ifi.dbs.elki.database.ids.DBIDArrayIter;
import de.lmu.ifi.dbs.elki.database.ids.DBIDUtil;
import de.lmu.ifi.dbs.elki.database.relation.Relation;
import de.lmu.ifi.dbs.elki.database.relation.RelationUtil;
import de.lmu.ifi.dbs.elki.datasource.FileBasedDatabaseConnection;


public class group_by_tcp_timestamp_elki
{
    /************************
     * Variables
    *************************/
    /* DEBUG */
    private static boolean DEBUG0 = true;
    private static boolean DEBUG1 = false;
    private static boolean DEBUG2 = true;

    /* Constant */
    private static double epsilon = 100;    /* used by DBScan alg. - radius to check neighbor nodes */
    private static int minpts     = 100;    /* used by DBScan alg. - min # of nodes in a cluster */


    /************************
     * main function
    *************************/
    public static void main(String[] args) throws Exception {

        /************************
         * Local variables
        *************************/
        String filename;
        Database db;
        Relation<? extends NumberVector<?>> rel;

        

        // Check # of input
        if (args.length == 0) {
            System.err.println("\nUsage: java group_by_tcp_timestamp filename target_ip\n");
            System.exit(1);
        }
        filename  = args[0];
        

        // Read input file
        if(DEBUG1) {
            System.out.println("input file name: " + filename);
            System.out.println();
        }
        
        ListParameterization database_params = new ListParameterization();
        database_params.addParameter(FileBasedDatabaseConnection.INPUT_ID, filename);
        db = ClassGenericsUtil.parameterizeOrAbort(StaticArrayDatabase.class, database_params);

        // double check parameters
        if (database_params.hasUnusedParameters()) {
            System.out.println("Unused parameters: " + database_params.getRemainingParameters());
            System.exit(1);
        }

        if (database_params.hasErrors()) {
            database_params.logAndClearReportedErrors();
            System.out.println("Parameterization errors.");
            System.exit(1);
        }

        // readin data
        db.initialize();
        rel = db.getRelation(TypeUtil.NUMBER_VECTOR_FIELD);


        // DEBUG: print out input file
        if(DEBUG1) {
        
            ArrayModifiableDBIDs ids = DBIDUtil.newArray(rel.getDBIDs());
            int dims = RelationUtil.dimensionality(rel);

            System.out.println("Num of dimension: " + dims);
            System.out.println("Relation size: " + rel.size() );

            for (int d = 0; d < dims; d++) {
                for (DBIDArrayIter it = ids.iter(); it.valid(); it.advance()) {
                    double value = rel.get(it).doubleValue(d);
                    System.out.println(value);
                }
            }
        
        } /* end DEBUG */


        // Initial DBSCAN
        ListParameterization params = new ListParameterization();
        params.addParameter(DBSCAN.EPSILON_ID, epsilon);
        params.addParameter(DBSCAN.MINPTS_ID, minpts);
        DBSCAN<? extends NumberVector<?>, DoubleDistance> dbscan = ClassGenericsUtil.parameterizeOrAbort(DBSCAN.class, params);

        Clustering<Model> result = dbscan.run(db);
        int cl_cnt = 0;
        for (Cluster<Model> cl : result.getAllClusters()) {
            System.out.println("cl " + cl_cnt + ": " + cl.toString());

            ArrayModifiableDBIDs ids = DBIDUtil.newArray(cl.getIDs());
            for (DBIDArrayIter it = ids.iter(); it.valid(); it.advance()) {
                double value = rel.get(it).doubleValue(0);
                System.out.println("Cluster " + cl_cnt + ": " + value);
            }
            cl_cnt ++;

        }

        
    }   /* end main */

}

