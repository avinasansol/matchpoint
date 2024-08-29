-- MySQL dump 10.13  Distrib 8.0.29, for Linux (x86_64)
--
-- Host: matchpoint.mysql.pythonanywhere-services.com    Database: matchpoint$matchpoint_db
-- ------------------------------------------------------
-- Server version	8.0.35

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `match`
--

DROP TABLE IF EXISTS `match`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `match` (
  `Match_Id` int NOT NULL AUTO_INCREMENT,
  `Series_Id` int NOT NULL,
  `Date_Time` datetime NOT NULL,
  `Place` varchar(15) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `Team_1` int NOT NULL,
  `Team_2` int NOT NULL,
  `Winner` enum('1','2') COLLATE utf8mb4_general_ci DEFAULT NULL,
  `Updated_By` int NOT NULL,
  `Updated_TS` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`Match_Id`),
  KEY `FK_Series_Id2_idx` (`Series_Id`),
  KEY `FK_Team_Id1_idx` (`Team_1`),
  KEY `FK_Team_Id2_idx` (`Team_2`),
  KEY `FK_Updated_By_Match` (`Updated_By`),
  CONSTRAINT `FK_Series_Id3` FOREIGN KEY (`Series_Id`) REFERENCES `series` (`Series_Id`),
  CONSTRAINT `FK_Team_Id1` FOREIGN KEY (`Team_1`) REFERENCES `team` (`Team_Id`),
  CONSTRAINT `FK_Team_Id2` FOREIGN KEY (`Team_2`) REFERENCES `team` (`Team_Id`),
  CONSTRAINT `FK_Updated_By_Match` FOREIGN KEY (`Updated_By`) REFERENCES `user` (`User_Id`)
) ENGINE=InnoDB AUTO_INCREMENT=71 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `match`
--

LOCK TABLES `match` WRITE;
/*!40000 ALTER TABLE `match` DISABLE KEYS */;
INSERT INTO `match` VALUES (1,1,'2024-03-22 19:30:00','Chennai',1,9,'1',10,'2024-03-29 20:09:16'),(2,1,'2024-03-23 15:00:00','Mohali',7,2,'1',10,'2024-03-29 20:09:28'),(3,1,'2024-03-23 19:00:00','Kolkata',4,10,'1',10,'2024-03-29 20:09:36'),(4,1,'2024-03-24 15:00:00','Jaipur ',8,5,'1',10,'2024-03-29 20:15:11'),(5,1,'2024-03-24 19:00:00','Ahmedabad',3,6,'1',10,'2024-03-29 20:18:43'),(6,1,'2024-03-25 19:00:00','Bengaluru',9,7,'1',10,'2024-03-29 20:24:55'),(7,1,'2024-03-26 19:00:00','Chennai',1,3,'1',10,'2024-03-30 10:43:13'),(8,1,'2024-03-27 19:00:00','Hyderabad',10,6,'1',10,'2024-03-30 10:52:20'),(9,1,'2024-03-28 19:00:00','Jaipur',8,2,'1',10,'2024-03-30 10:56:10'),(10,1,'2024-03-29 19:00:00','Bengaluru',9,4,'2',10,'2024-03-31 06:32:08'),(11,1,'2024-03-30 19:00:00','Lucknow',5,7,'1',10,'2024-03-31 06:51:19'),(12,1,'2024-03-31 15:00:00','Ahmedabad',3,10,'1',10,'2024-03-31 13:24:20'),(13,1,'2024-03-31 19:00:00','Visakhapatnam',2,1,'1',10,'2024-03-31 18:52:15'),(14,1,'2024-04-01 19:00:00','Mumbai',6,8,'2',4,'2024-04-01 17:28:44'),(15,1,'2024-04-02 19:00:00','Bengaluru',9,5,'2',4,'2024-04-02 17:38:38'),(16,1,'2024-04-03 19:00:00','Visakhapatnam',2,4,'2',4,'2024-04-03 18:04:26'),(17,1,'2024-04-04 19:00:00','Ahmedabad',3,7,'2',4,'2024-04-04 17:45:37'),(18,1,'2024-04-05 19:00:00','Hyderabad',10,1,'1',4,'2024-04-05 17:21:27'),(19,1,'2024-04-06 19:00:00','Jaipur',8,9,'1',4,'2024-04-06 17:37:22'),(20,1,'2024-04-07 15:00:00','Mumbai',6,2,'1',4,'2024-04-07 13:48:13'),(21,1,'2024-04-07 19:00:00','Lucknow',5,3,'1',4,'2024-04-07 17:45:32'),(22,1,'2024-04-08 19:00:00','Chennai',1,4,'1',5,'2024-04-08 17:43:04'),(23,1,'2024-04-09 19:00:00','Mohali',7,10,'2',4,'2024-04-09 17:44:25'),(24,1,'2024-04-10 19:00:00','Jaipur',8,3,'2',4,'2024-04-10 18:18:38'),(25,1,'2024-04-11 19:00:00','Mumbai',6,9,'1',4,'2024-04-11 17:46:37'),(26,1,'2024-04-12 19:00:00','Lucknow',5,2,'2',4,'2024-04-12 17:42:14'),(27,1,'2024-04-13 19:00:00','Mohali',7,8,NULL,10,'2024-03-29 07:12:57'),(28,1,'2024-04-14 15:00:00','Kolkata',4,5,NULL,10,'2024-03-29 07:12:57'),(29,1,'2024-04-14 19:00:00','Mumbai',6,1,NULL,10,'2024-03-29 07:12:57'),(30,1,'2024-04-15 19:00:00','Bengaluru',9,10,NULL,10,'2024-03-29 07:12:57'),(31,1,'2024-04-16 19:00:00','Ahmedabad',3,2,NULL,10,'2024-03-29 07:12:57'),(32,1,'2024-04-17 19:00:00','Kolkata',4,8,NULL,10,'2024-03-29 07:12:57'),(33,1,'2024-04-18 19:00:00','Mohali',7,6,NULL,10,'2024-03-29 07:12:57'),(34,1,'2024-04-19 19:00:00','Lucknow',5,1,NULL,10,'2024-03-29 07:12:57'),(35,1,'2024-04-20 19:00:00','Delhi',2,10,NULL,10,'2024-03-29 07:12:57'),(36,1,'2024-04-21 15:00:00','Kolkata',4,9,NULL,10,'2024-03-29 07:12:57'),(37,1,'2024-04-21 19:00:00','Mohali',7,3,NULL,10,'2024-03-29 07:12:57'),(38,1,'2024-04-22 19:00:00','Jaipur',8,6,NULL,10,'2024-03-29 07:12:57'),(39,1,'2024-04-23 19:00:00','Chennai',1,5,NULL,10,'2024-03-29 07:12:57'),(40,1,'2024-04-24 19:00:00','Delhi',2,3,NULL,10,'2024-03-29 07:12:57'),(41,1,'2024-04-25 19:00:00','Hyderabad',10,9,NULL,10,'2024-03-29 07:12:57'),(42,1,'2024-04-26 19:00:00','Kolkata',4,7,NULL,10,'2024-03-29 07:12:57'),(43,1,'2024-04-27 15:00:00','Delhi',2,6,NULL,10,'2024-03-29 07:12:57'),(44,1,'2024-04-27 19:00:00','Lucknow',5,8,NULL,10,'2024-03-29 07:12:57'),(45,1,'2024-04-28 19:00:00','Ahmedabad',3,9,NULL,10,'2024-03-29 07:12:57'),(46,1,'2024-04-28 19:00:00','Chennai',1,10,NULL,10,'2024-03-29 07:12:57'),(47,1,'2024-04-29 19:00:00','Kolkata',4,2,NULL,10,'2024-03-29 07:12:57'),(48,1,'2024-04-30 19:00:00','Lucknow',5,6,NULL,10,'2024-03-29 07:12:57'),(49,1,'2024-05-01 19:00:00','Chennai',1,7,NULL,10,'2024-03-29 07:12:57'),(50,1,'2024-05-02 19:00:00','Hyderabad',10,8,NULL,10,'2024-03-29 07:12:57'),(51,1,'2024-05-03 19:00:00','Mumbai',6,4,NULL,10,'2024-03-29 07:12:57'),(52,1,'2024-05-04 19:00:00','Bengaluru',9,3,NULL,10,'2024-03-29 07:12:57'),(53,1,'2024-05-05 15:00:00','Dharamshala',7,1,NULL,10,'2024-03-29 07:12:57'),(54,1,'2024-05-05 19:00:00','Lucknow',5,4,NULL,10,'2024-03-29 07:12:57'),(55,1,'2024-05-06 19:00:00','Mumbai',6,10,NULL,10,'2024-03-29 07:12:57'),(56,1,'2024-05-07 19:00:00','Delhi',2,8,NULL,10,'2024-03-29 07:12:57'),(57,1,'2024-05-08 19:00:00','Hyderabad',10,5,NULL,10,'2024-03-29 07:12:57'),(58,1,'2024-05-09 19:00:00','Dharamshala',7,9,NULL,10,'2024-03-29 07:12:57'),(59,1,'2024-05-10 19:00:00','Ahmedabad',3,1,NULL,10,'2024-03-29 07:12:57'),(60,1,'2024-05-11 19:00:00','Kolkata',4,6,NULL,10,'2024-03-29 07:12:57'),(61,1,'2024-05-12 15:00:00','Chennai',1,8,NULL,10,'2024-03-29 07:12:57'),(62,1,'2024-05-12 19:00:00','Bengaluru',9,2,NULL,10,'2024-03-29 07:12:57'),(63,1,'2024-05-13 19:00:00','Ahmedabad',3,4,NULL,10,'2024-03-29 07:12:57'),(64,1,'2024-05-14 19:00:00','Delhi',2,5,NULL,10,'2024-03-29 07:12:57'),(65,1,'2024-05-15 19:00:00','Guwahati',8,7,NULL,10,'2024-03-29 07:12:57'),(66,1,'2024-05-16 19:00:00','Hyderabad',10,3,NULL,10,'2024-03-29 07:12:57'),(67,1,'2024-05-17 19:00:00','Mumbai',6,5,NULL,10,'2024-03-29 07:12:57'),(68,1,'2024-05-18 19:00:00','Bengaluru',9,1,NULL,10,'2024-03-29 07:12:57'),(69,1,'2024-05-19 15:00:00','Hyderabad',10,7,NULL,10,'2024-03-29 07:12:57'),(70,1,'2024-05-19 19:00:00','Guwahati',8,4,NULL,10,'2024-03-29 07:12:57');
/*!40000 ALTER TABLE `match` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `poll`
--

DROP TABLE IF EXISTS `poll`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `poll` (
  `Match_Id` int NOT NULL,
  `User_Id` int NOT NULL,
  `Poll_Team` int DEFAULT NULL,
  `Points` int DEFAULT NULL,
  `Updated_By` int NOT NULL,
  `Updated_TS` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`Match_Id`,`User_Id`),
  KEY `FK_Match_Id_idx` (`Match_Id`),
  KEY `FK_User_Id2_idx` (`User_Id`),
  KEY `FK_Team_Poll_idx` (`Poll_Team`),
  KEY `FK_Updated_By_Poll` (`Updated_By`),
  CONSTRAINT `FK_Match_Id` FOREIGN KEY (`Match_Id`) REFERENCES `match` (`Match_Id`),
  CONSTRAINT `FK_Team_Poll` FOREIGN KEY (`Poll_Team`) REFERENCES `team` (`Team_Id`),
  CONSTRAINT `FK_Updated_By_Poll` FOREIGN KEY (`Updated_By`) REFERENCES `user` (`User_Id`),
  CONSTRAINT `FK_User_Id2` FOREIGN KEY (`User_Id`) REFERENCES `user` (`User_Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `poll`
--

LOCK TABLES `poll` WRITE;
/*!40000 ALTER TABLE `poll` DISABLE KEYS */;
INSERT INTO `poll` VALUES (1,1,1,12,10,'2024-03-29 18:42:44'),(1,2,9,-20,10,'2024-03-29 18:55:07'),(1,3,9,-20,10,'2024-03-29 18:55:07'),(1,4,1,12,10,'2024-03-29 18:43:06'),(1,5,1,12,10,'2024-03-29 18:43:11'),(1,6,1,12,10,'2024-03-29 18:43:16'),(1,7,1,12,10,'2024-03-29 18:43:21'),(1,8,9,-20,10,'2024-03-29 18:55:07'),(1,9,1,12,10,'2024-03-29 18:43:35'),(1,10,1,12,10,'2024-03-29 18:43:40'),(1,11,NULL,-20,10,'2024-03-29 18:55:07'),(1,12,9,-20,10,'2024-03-29 18:55:07'),(1,13,1,12,10,'2024-03-29 18:43:56'),(1,14,1,12,10,'2024-03-29 18:44:02'),(1,15,1,12,10,'2024-03-29 18:44:10'),(1,16,9,-20,10,'2024-03-29 18:55:07'),(2,1,NULL,-20,10,'2024-03-29 19:05:12'),(2,2,7,26,10,'2024-03-29 19:00:06'),(2,3,7,26,10,'2024-03-29 19:00:19'),(2,4,NULL,-20,10,'2024-03-29 19:05:12'),(2,5,7,26,10,'2024-03-29 19:00:33'),(2,6,7,26,10,'2024-03-29 19:00:36'),(2,7,NULL,-20,10,'2024-03-29 19:05:12'),(2,8,7,26,10,'2024-03-29 19:00:48'),(2,9,NULL,-20,10,'2024-03-29 19:05:12'),(2,10,2,-20,10,'2024-03-29 19:01:40'),(2,11,NULL,-20,10,'2024-03-29 19:05:12'),(2,12,7,26,10,'2024-03-29 19:01:01'),(2,13,NULL,-20,10,'2024-03-29 19:05:12'),(2,14,7,26,10,'2024-03-29 19:01:14'),(2,15,NULL,-20,10,'2024-03-29 19:05:12'),(2,16,NULL,-20,10,'2024-03-29 19:05:12'),(3,1,4,16,10,'2024-03-29 19:59:56'),(3,2,4,16,10,'2024-03-29 20:00:07'),(3,3,NULL,-20,10,'2024-03-29 20:03:18'),(3,4,NULL,-20,10,'2024-03-29 20:03:18'),(3,5,NULL,-20,10,'2024-03-29 20:03:19'),(3,6,4,16,10,'2024-03-29 20:00:22'),(3,7,NULL,-20,10,'2024-03-29 20:03:19'),(3,8,4,16,10,'2024-03-29 20:00:35'),(3,9,4,16,10,'2024-03-29 20:00:40'),(3,10,4,16,10,'2024-03-29 20:00:45'),(3,11,NULL,-20,10,'2024-03-29 20:03:19'),(3,12,4,16,10,'2024-03-29 20:00:59'),(3,13,4,16,10,'2024-03-29 20:01:04'),(3,14,NULL,-20,10,'2024-03-29 20:03:19'),(3,15,NULL,-20,10,'2024-03-29 20:03:19'),(3,16,4,16,10,'2024-03-29 20:01:18'),(4,1,8,20,10,'2024-03-29 20:12:30'),(4,2,NULL,-20,10,'2024-03-29 20:15:11'),(4,3,NULL,-20,10,'2024-03-29 20:15:11'),(4,4,NULL,-20,10,'2024-03-29 20:15:11'),(4,5,8,20,10,'2024-03-29 20:12:40'),(4,6,8,20,10,'2024-03-29 20:12:47'),(4,7,8,20,10,'2024-03-29 20:12:53'),(4,8,8,20,10,'2024-03-29 20:12:58'),(4,9,NULL,-20,10,'2024-03-29 20:15:11'),(4,10,8,20,10,'2024-03-29 20:13:13'),(4,11,NULL,-20,10,'2024-03-29 20:15:11'),(4,12,8,20,10,'2024-03-29 20:13:33'),(4,13,NULL,-20,10,'2024-03-29 20:15:11'),(4,14,8,20,10,'2024-03-29 20:13:53'),(4,15,NULL,-20,10,'2024-03-29 20:15:11'),(4,16,NULL,-20,10,'2024-03-29 20:15:11'),(5,1,NULL,-20,10,'2024-03-29 20:18:43'),(5,2,NULL,-20,10,'2024-03-29 20:18:43'),(5,3,NULL,-20,10,'2024-03-29 20:18:43'),(5,4,3,60,10,'2024-03-29 20:16:55'),(5,5,3,60,10,'2024-03-29 20:17:03'),(5,6,NULL,-20,10,'2024-03-29 20:18:43'),(5,7,NULL,-20,10,'2024-03-29 20:18:43'),(5,8,NULL,-20,10,'2024-03-29 20:18:43'),(5,9,NULL,-20,10,'2024-03-29 20:18:43'),(5,10,NULL,-20,10,'2024-03-29 20:18:43'),(5,11,NULL,-20,10,'2024-03-29 20:18:43'),(5,12,3,60,10,'2024-03-29 20:17:25'),(5,13,NULL,-20,10,'2024-03-29 20:18:43'),(5,14,NULL,-20,10,'2024-03-29 20:18:43'),(5,15,3,60,10,'2024-03-29 20:17:32'),(5,16,NULL,-20,10,'2024-03-29 20:18:43'),(6,1,9,16,10,'2024-03-29 20:22:33'),(6,2,NULL,-20,10,'2024-03-29 20:24:55'),(6,3,9,16,10,'2024-03-29 20:22:45'),(6,4,NULL,-20,10,'2024-03-29 20:24:55'),(6,5,NULL,-20,10,'2024-03-29 20:24:55'),(6,6,9,16,10,'2024-03-29 20:22:53'),(6,7,9,16,10,'2024-03-29 20:22:58'),(6,8,NULL,-20,10,'2024-03-29 20:24:55'),(6,9,9,16,10,'2024-03-29 20:23:15'),(6,10,NULL,-20,10,'2024-03-29 20:24:55'),(6,11,9,16,10,'2024-03-29 20:23:21'),(6,12,9,16,10,'2024-03-29 20:23:28'),(6,13,NULL,-20,10,'2024-03-29 20:24:55'),(6,14,9,16,10,'2024-03-29 20:23:50'),(6,15,9,16,10,'2024-03-29 20:23:56'),(6,16,NULL,-20,10,'2024-03-29 20:24:55'),(7,1,NULL,-20,10,'2024-03-30 10:43:13'),(7,2,NULL,-20,10,'2024-03-30 10:43:13'),(7,3,1,16,10,'2024-03-30 10:40:54'),(7,4,1,16,10,'2024-03-30 10:40:59'),(7,5,1,16,10,'2024-03-30 10:41:05'),(7,6,1,16,10,'2024-03-30 10:41:09'),(7,7,1,16,10,'2024-03-30 10:41:14'),(7,8,NULL,-20,10,'2024-03-30 10:43:13'),(7,9,1,16,10,'2024-03-30 10:41:28'),(7,10,1,16,10,'2024-03-30 10:41:33'),(7,11,1,16,10,'2024-03-30 10:41:38'),(7,12,NULL,-20,10,'2024-03-30 10:43:13'),(7,13,NULL,-20,10,'2024-03-30 10:43:13'),(7,14,1,16,10,'2024-03-30 10:41:55'),(7,15,NULL,-20,10,'2024-03-30 10:43:13'),(7,16,NULL,-20,10,'2024-03-30 10:43:13'),(8,1,NULL,-20,10,'2024-03-30 10:52:20'),(8,2,NULL,-20,10,'2024-03-30 10:52:20'),(8,3,10,26,10,'2024-03-30 10:49:09'),(8,4,10,26,10,'2024-03-30 10:49:13'),(8,5,10,26,10,'2024-03-30 10:49:18'),(8,6,10,26,10,'2024-03-30 10:49:23'),(8,7,10,26,10,'2024-03-30 10:49:27'),(8,8,NULL,-20,10,'2024-03-30 10:52:20'),(8,9,10,26,10,'2024-03-30 10:50:10'),(8,10,NULL,-20,10,'2024-03-30 10:52:20'),(8,11,NULL,-20,10,'2024-03-30 10:52:20'),(8,12,10,26,10,'2024-03-30 10:50:23'),(8,13,NULL,-20,10,'2024-03-30 10:52:20'),(8,14,NULL,-20,10,'2024-03-30 10:52:20'),(8,15,NULL,-20,10,'2024-03-30 10:52:20'),(8,16,NULL,-20,10,'2024-03-30 10:52:20'),(9,1,8,9,10,'2024-03-30 10:53:46'),(9,2,NULL,-20,10,'2024-03-30 10:56:10'),(9,3,8,9,10,'2024-03-30 10:53:52'),(9,4,NULL,-20,10,'2024-03-30 10:56:10'),(9,5,8,9,10,'2024-03-30 10:53:57'),(9,6,8,9,10,'2024-03-30 10:54:02'),(9,7,8,9,10,'2024-03-30 10:54:08'),(9,8,8,9,10,'2024-03-30 10:54:28'),(9,9,8,9,10,'2024-03-30 10:54:32'),(9,10,NULL,-20,10,'2024-03-30 10:56:10'),(9,11,8,9,10,'2024-03-30 10:54:49'),(9,12,NULL,-20,10,'2024-03-30 10:56:10'),(9,13,8,9,10,'2024-03-30 10:54:55'),(9,14,8,9,10,'2024-03-30 10:54:58'),(9,15,8,9,10,'2024-03-30 10:55:02'),(9,16,NULL,-20,10,'2024-03-30 10:56:10'),(10,1,4,26,10,'2024-03-31 06:26:43'),(10,2,9,-20,10,'2024-03-31 06:27:51'),(10,3,9,-20,10,'2024-03-31 06:28:05'),(10,4,4,26,10,'2024-03-31 06:25:18'),(10,5,9,-20,10,'2024-03-31 06:27:18'),(10,6,4,26,10,'2024-03-31 06:26:27'),(10,7,4,26,10,'2024-03-31 06:25:44'),(10,8,NULL,-20,10,'2024-03-31 06:32:09'),(10,9,4,26,10,'2024-03-31 06:25:26'),(10,10,9,-20,10,'2024-03-31 06:27:36'),(10,11,9,-20,10,'2024-03-31 06:28:15'),(10,12,9,-20,10,'2024-03-31 06:27:26'),(10,13,9,-20,10,'2024-03-31 06:28:20'),(10,14,4,26,10,'2024-03-31 06:26:08'),(10,15,4,26,10,'2024-03-31 06:26:01'),(10,16,NULL,-20,10,'2024-03-31 06:32:09'),(11,1,5,20,10,'2024-03-31 06:38:23'),(11,2,7,-20,10,'2024-03-31 06:41:29'),(11,3,5,20,10,'2024-03-31 06:39:48'),(11,4,5,20,10,'2024-03-31 06:39:53'),(11,5,7,-20,10,'2024-03-31 06:42:15'),(11,6,7,-20,10,'2024-03-31 06:42:23'),(11,7,7,-20,10,'2024-03-31 06:42:28'),(11,8,5,20,10,'2024-03-31 06:40:02'),(11,9,5,20,10,'2024-03-31 06:38:43'),(11,10,7,-20,10,'2024-03-31 06:41:48'),(11,11,5,20,10,'2024-03-31 06:39:18'),(11,12,7,-20,10,'2024-03-31 06:41:39'),(11,13,7,-20,10,'2024-03-31 06:42:35'),(11,14,5,20,10,'2024-03-31 06:39:05'),(11,15,5,20,10,'2024-03-31 06:38:59'),(11,16,NULL,-20,10,'2024-03-31 06:51:19'),(12,1,10,-20,10,'2024-03-31 11:32:06'),(12,2,3,33,10,'2024-03-31 11:31:01'),(12,3,10,-20,10,'2024-03-31 11:33:09'),(12,4,10,-20,10,'2024-03-31 11:33:15'),(12,5,10,-20,10,'2024-03-31 11:32:17'),(12,6,10,-20,10,'2024-03-31 11:33:21'),(12,7,10,-20,10,'2024-03-31 11:33:26'),(12,8,10,-20,10,'2024-03-31 11:33:32'),(12,9,10,-20,10,'2024-03-31 11:32:36'),(12,10,3,33,10,'2024-03-31 11:30:32'),(12,11,10,-20,10,'2024-03-31 11:32:26'),(12,12,3,33,10,'2024-03-31 11:31:11'),(12,13,3,33,10,'2024-03-31 11:31:17'),(12,14,3,33,10,'2024-03-31 11:31:29'),(12,15,3,33,10,'2024-03-31 11:31:35'),(12,16,NULL,-20,10,'2024-03-31 13:24:20'),(13,1,1,-20,10,'2024-03-31 11:38:14'),(13,2,2,87,10,'2024-03-31 11:37:13'),(13,3,1,-20,10,'2024-03-31 11:38:21'),(13,4,2,87,10,'2024-03-31 11:37:20'),(13,5,1,-20,10,'2024-03-31 11:38:40'),(13,6,1,-20,10,'2024-03-31 11:38:45'),(13,7,1,-20,10,'2024-03-31 11:38:49'),(13,8,1,-20,10,'2024-03-31 11:38:54'),(13,9,1,-20,10,'2024-03-31 11:38:58'),(13,10,1,-20,10,'2024-03-31 11:36:46'),(13,11,1,-20,10,'2024-03-31 11:39:03'),(13,12,2,87,10,'2024-03-31 11:37:37'),(13,13,1,-20,10,'2024-03-31 11:39:08'),(13,14,1,-20,10,'2024-03-31 11:39:12'),(13,15,1,-20,10,'2024-03-31 11:39:17'),(13,16,NULL,-20,10,'2024-03-31 18:52:15'),(14,1,8,33,4,'2024-04-01 13:04:31'),(14,2,8,33,4,'2024-04-01 12:39:13'),(14,3,8,33,4,'2024-04-01 12:39:21'),(14,4,8,33,4,'2024-04-01 12:39:28'),(14,5,6,-20,5,'2024-04-01 09:02:56'),(14,6,8,33,4,'2024-04-01 12:39:35'),(14,7,6,-20,7,'2024-04-01 12:32:06'),(14,8,6,-20,4,'2024-04-01 12:45:12'),(14,9,NULL,-20,4,'2024-04-01 17:28:44'),(14,10,6,-20,4,'2024-04-01 12:45:36'),(14,11,6,-20,4,'2024-04-01 12:44:41'),(14,12,8,33,4,'2024-04-01 12:39:54'),(14,13,6,-20,4,'2024-04-01 12:45:43'),(14,14,6,-20,4,'2024-04-01 12:44:52'),(14,15,6,-20,4,'2024-04-01 12:45:01'),(14,16,6,-20,4,'2024-04-01 13:10:15'),(15,1,5,60,1,'2024-04-02 03:20:37'),(15,2,5,60,2,'2024-04-02 05:30:31'),(15,3,9,-20,3,'2024-04-02 03:43:02'),(15,4,5,60,4,'2024-04-02 04:24:25'),(15,5,9,-20,5,'2024-04-02 04:35:39'),(15,6,5,60,6,'2024-04-02 05:33:03'),(15,7,9,-20,7,'2024-04-02 06:43:43'),(15,8,9,-20,8,'2024-04-02 08:17:44'),(15,9,9,-20,9,'2024-04-02 05:00:05'),(15,10,9,-20,10,'2024-04-02 05:28:26'),(15,11,NULL,-20,4,'2024-04-02 17:38:38'),(15,12,9,-20,12,'2024-04-02 03:51:28'),(15,13,9,-20,13,'2024-04-02 10:53:50'),(15,14,9,-20,14,'2024-04-01 16:34:00'),(15,15,NULL,-20,4,'2024-04-02 17:38:38'),(15,16,9,-20,16,'2024-04-02 13:23:28'),(16,1,4,16,1,'2024-04-03 04:18:30'),(16,2,4,16,2,'2024-04-03 09:20:21'),(16,3,4,16,3,'2024-04-03 06:03:14'),(16,4,2,-20,4,'2024-04-03 04:09:01'),(16,5,2,-20,5,'2024-04-03 09:22:36'),(16,6,4,16,6,'2024-04-03 04:14:19'),(16,7,4,16,7,'2024-04-03 09:49:31'),(16,8,NULL,-20,4,'2024-04-03 18:04:26'),(16,9,4,16,9,'2024-04-03 04:14:22'),(16,10,2,-20,10,'2024-04-03 06:18:33'),(16,11,NULL,-20,4,'2024-04-03 18:04:26'),(16,12,2,-20,12,'2024-04-03 11:40:55'),(16,13,4,16,13,'2024-04-03 09:20:26'),(16,14,4,16,14,'2024-04-03 04:36:36'),(16,15,4,16,15,'2024-04-03 04:19:25'),(16,16,NULL,-20,4,'2024-04-03 18:04:26'),(17,1,3,-20,1,'2024-04-04 10:46:15'),(17,2,7,33,2,'2024-04-04 13:10:41'),(17,3,3,-20,3,'2024-04-03 15:28:11'),(17,4,7,33,4,'2024-04-04 05:13:44'),(17,5,7,33,5,'2024-04-04 12:49:11'),(17,6,3,-20,6,'2024-04-04 05:15:26'),(17,7,NULL,-20,4,'2024-04-04 17:45:37'),(17,8,7,33,8,'2024-04-04 06:18:12'),(17,9,3,-20,9,'2024-04-04 05:22:34'),(17,10,7,33,10,'2024-04-04 05:24:52'),(17,11,NULL,-20,4,'2024-04-04 17:45:37'),(17,12,7,33,12,'2024-04-04 13:16:24'),(17,13,NULL,-20,4,'2024-04-04 17:45:37'),(17,14,3,-20,14,'2024-04-04 06:19:24'),(17,15,3,-20,15,'2024-04-04 09:48:23'),(17,16,NULL,-20,4,'2024-04-04 17:45:37'),(18,1,1,-20,1,'2024-04-05 09:13:51'),(18,2,1,-20,2,'2024-04-05 08:57:23'),(18,3,10,26,3,'2024-04-05 07:04:14'),(18,4,1,-20,4,'2024-04-05 08:57:11'),(18,5,1,-20,5,'2024-04-05 09:01:44'),(18,6,10,26,6,'2024-04-05 06:58:12'),(18,7,10,26,7,'2024-04-05 08:54:05'),(18,8,10,26,8,'2024-04-05 03:52:58'),(18,9,1,-20,9,'2024-04-05 08:58:01'),(18,10,10,26,10,'2024-04-04 18:07:51'),(18,11,NULL,-20,4,'2024-04-05 17:21:27'),(18,12,10,26,12,'2024-04-05 12:53:04'),(18,13,1,-20,13,'2024-04-05 08:56:00'),(18,14,NULL,-20,4,'2024-04-05 17:21:27'),(18,15,10,26,15,'2024-04-05 08:57:46'),(18,16,NULL,-20,4,'2024-04-05 17:21:27'),(19,1,8,26,1,'2024-04-06 11:02:46'),(19,2,NULL,-20,4,'2024-04-06 17:37:22'),(19,3,9,-20,3,'2024-04-06 09:38:58'),(19,4,8,26,4,'2024-04-06 10:17:12'),(19,5,9,-20,5,'2024-04-06 11:51:50'),(19,6,8,26,6,'2024-04-06 10:34:02'),(19,7,8,26,7,'2024-04-06 12:56:41'),(19,8,8,26,8,'2024-04-06 11:36:19'),(19,9,8,26,9,'2024-04-06 10:30:57'),(19,10,9,-20,10,'2024-04-06 10:58:13'),(19,11,NULL,-20,4,'2024-04-06 17:37:22'),(19,12,9,-20,12,'2024-04-06 12:09:54'),(19,13,NULL,-20,4,'2024-04-06 17:37:22'),(19,14,NULL,-20,4,'2024-04-06 17:37:22'),(19,15,8,26,15,'2024-04-06 10:25:32'),(19,16,NULL,-20,4,'2024-04-06 17:37:22'),(20,1,6,12,1,'2024-04-07 05:22:31'),(20,2,6,12,2,'2024-04-07 08:08:57'),(20,3,6,12,3,'2024-04-06 09:38:42'),(20,4,6,12,4,'2024-04-07 09:27:28'),(20,5,6,12,5,'2024-04-07 09:02:53'),(20,6,2,-20,6,'2024-04-07 09:22:18'),(20,7,6,12,7,'2024-04-07 05:16:11'),(20,8,6,12,8,'2024-04-06 11:36:08'),(20,9,NULL,-20,4,'2024-04-07 13:48:13'),(20,10,6,12,10,'2024-04-07 06:06:38'),(20,11,NULL,-20,4,'2024-04-07 13:48:13'),(20,12,NULL,-20,4,'2024-04-07 13:48:13'),(20,13,6,12,13,'2024-04-07 07:23:38'),(20,14,NULL,-20,4,'2024-04-07 13:48:13'),(20,15,6,12,15,'2024-04-07 05:18:13'),(20,16,NULL,-20,4,'2024-04-07 13:48:13'),(21,1,3,-20,1,'2024-04-07 05:26:19'),(21,2,5,60,2,'2024-04-07 08:09:12'),(21,3,5,60,3,'2024-04-07 07:12:21'),(21,4,5,60,4,'2024-04-07 09:28:43'),(21,5,3,-20,5,'2024-04-07 13:10:53'),(21,6,NULL,-20,4,'2024-04-07 17:45:32'),(21,7,NULL,-20,4,'2024-04-07 17:45:32'),(21,8,NULL,-20,4,'2024-04-07 17:45:32'),(21,9,NULL,-20,4,'2024-04-07 17:45:32'),(21,10,3,-20,10,'2024-04-07 06:07:00'),(21,11,NULL,-20,4,'2024-04-07 17:45:32'),(21,12,3,-20,12,'2024-04-07 13:23:12'),(21,13,5,60,13,'2024-04-07 13:06:37'),(21,14,NULL,-20,4,'2024-04-07 17:45:32'),(21,15,NULL,-20,4,'2024-04-07 17:45:32'),(21,16,NULL,-20,4,'2024-04-07 17:45:32'),(22,1,4,-20,1,'2024-04-07 18:05:43'),(22,2,1,44,2,'2024-04-08 06:03:01'),(22,3,1,44,3,'2024-04-07 13:39:42'),(22,4,1,44,4,'2024-04-07 17:46:57'),(22,5,1,44,5,'2024-04-08 08:42:24'),(22,6,4,-20,6,'2024-04-08 06:07:33'),(22,7,4,-20,7,'2024-04-08 01:31:01'),(22,8,4,-20,8,'2024-04-08 06:00:39'),(22,9,4,-20,9,'2024-04-08 00:19:31'),(22,10,4,-20,10,'2024-04-07 18:41:01'),(22,11,NULL,-20,5,'2024-04-08 17:43:04'),(22,12,NULL,-20,5,'2024-04-08 17:43:04'),(22,13,1,44,13,'2024-04-08 09:12:01'),(22,14,NULL,-20,5,'2024-04-08 17:43:04'),(22,15,4,-20,15,'2024-04-07 17:52:31'),(22,16,NULL,-20,5,'2024-04-08 17:43:04'),(23,1,10,20,1,'2024-04-09 10:20:03'),(23,2,7,-20,2,'2024-04-09 11:29:41'),(23,3,10,20,3,'2024-04-09 03:17:28'),(23,4,7,-20,4,'2024-04-09 02:57:58'),(23,5,10,20,5,'2024-04-09 07:13:58'),(23,6,7,-20,6,'2024-04-09 03:12:02'),(23,7,10,20,7,'2024-04-09 03:12:40'),(23,8,10,20,8,'2024-04-09 04:25:51'),(23,9,10,20,9,'2024-04-09 03:03:42'),(23,10,7,-20,10,'2024-04-09 03:20:15'),(23,11,NULL,-20,4,'2024-04-09 17:44:25'),(23,12,7,-20,12,'2024-04-09 11:49:37'),(23,13,10,20,13,'2024-04-09 09:09:10'),(23,14,NULL,-20,4,'2024-04-09 17:44:25'),(23,15,10,20,15,'2024-04-09 04:43:15'),(23,16,NULL,-20,4,'2024-04-09 17:44:25'),(24,1,8,-20,1,'2024-04-10 06:43:57'),(24,2,3,44,2,'2024-04-10 10:06:30'),(24,3,8,-20,3,'2024-04-09 18:39:56'),(24,4,8,-20,4,'2024-04-10 05:49:52'),(24,5,3,44,5,'2024-04-10 07:49:17'),(24,6,8,-20,6,'2024-04-10 05:57:13'),(24,7,8,-20,7,'2024-04-10 05:51:58'),(24,8,8,-20,8,'2024-04-10 07:15:40'),(24,9,8,-20,9,'2024-04-10 06:56:08'),(24,10,3,44,10,'2024-04-10 10:08:40'),(24,11,NULL,-20,4,'2024-04-10 18:18:38'),(24,12,3,44,12,'2024-04-10 13:12:39'),(24,13,8,-20,13,'2024-04-10 05:54:13'),(24,14,NULL,-20,4,'2024-04-10 18:18:38'),(24,15,3,44,15,'2024-04-10 06:00:54'),(24,16,NULL,-20,4,'2024-04-10 18:18:38'),(25,1,6,26,1,'2024-04-11 09:01:33'),(25,2,9,-20,2,'2024-04-11 04:54:07'),(25,3,9,-20,3,'2024-04-11 03:19:58'),(25,4,6,26,4,'2024-04-11 02:58:01'),(25,5,6,26,5,'2024-04-11 08:26:04'),(25,6,6,26,6,'2024-04-11 03:51:29'),(25,7,9,-20,7,'2024-04-11 10:19:34'),(25,8,NULL,-20,4,'2024-04-11 17:46:37'),(25,9,6,26,9,'2024-04-11 09:59:55'),(25,10,6,26,10,'2024-04-11 11:52:50'),(25,11,NULL,-20,4,'2024-04-11 17:46:37'),(25,12,NULL,-20,4,'2024-04-11 17:46:37'),(25,13,9,-20,13,'2024-04-11 07:05:16'),(25,14,NULL,-20,4,'2024-04-11 17:46:37'),(25,15,6,26,15,'2024-04-11 03:58:41'),(25,16,NULL,-20,4,'2024-04-11 17:46:37'),(26,1,5,-20,1,'2024-04-12 07:40:55'),(26,2,5,-20,2,'2024-04-12 12:47:03'),(26,3,5,-20,3,'2024-04-12 06:40:05'),(26,4,5,-20,4,'2024-04-12 05:01:57'),(26,5,2,60,5,'2024-04-12 13:09:44'),(26,6,5,-20,6,'2024-04-12 05:06:43'),(26,7,5,-20,7,'2024-04-12 08:06:57'),(26,8,2,60,8,'2024-04-12 08:03:10'),(26,9,5,-20,9,'2024-04-12 06:16:49'),(26,10,2,60,10,'2024-04-11 20:25:31'),(26,11,NULL,-20,4,'2024-04-12 17:42:14'),(26,12,2,60,12,'2024-04-12 05:18:54'),(26,13,NULL,-20,4,'2024-04-12 17:42:14'),(26,14,NULL,-20,4,'2024-04-12 17:42:15'),(26,15,5,-20,15,'2024-04-12 05:06:06'),(26,16,NULL,-20,4,'2024-04-12 17:42:15'),(27,8,8,NULL,8,'2024-04-12 18:50:28');
/*!40000 ALTER TABLE `poll` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `series`
--

DROP TABLE IF EXISTS `series`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `series` (
  `Series_Id` int NOT NULL AUTO_INCREMENT,
  `Series_Name` varchar(58) COLLATE utf8mb4_general_ci NOT NULL,
  `Updated_By` int NOT NULL,
  `Updated_TS` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`Series_Id`),
  KEY `FK_Updated_By_Series` (`Updated_By`),
  CONSTRAINT `FK_Updated_By_Series` FOREIGN KEY (`Updated_By`) REFERENCES `user` (`User_Id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `series`
--

LOCK TABLES `series` WRITE;
/*!40000 ALTER TABLE `series` DISABLE KEYS */;
INSERT INTO `series` VALUES (1,'IPL 2024 - Indian Premier League',10,'2024-03-29 06:29:33');
/*!40000 ALTER TABLE `series` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `series_user`
--

DROP TABLE IF EXISTS `series_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `series_user` (
  `Series_Id` int NOT NULL,
  `User_Id` int NOT NULL,
  `Points` int DEFAULT NULL,
  `Updated_By` int NOT NULL,
  `Updated_TS` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`Series_Id`,`User_Id`),
  KEY `FK_Series_Id_idx` (`Series_Id`),
  KEY `FK_User_Id_idx` (`User_Id`),
  KEY `FK_Updated_By_Series_User` (`Updated_By`),
  CONSTRAINT `FK_Series_Id2` FOREIGN KEY (`Series_Id`) REFERENCES `series` (`Series_Id`),
  CONSTRAINT `FK_Updated_By_Series_User` FOREIGN KEY (`Updated_By`) REFERENCES `user` (`User_Id`),
  CONSTRAINT `FK_User_Id` FOREIGN KEY (`User_Id`) REFERENCES `user` (`User_Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `series_user`
--

LOCK TABLES `series_user` WRITE;
/*!40000 ALTER TABLE `series_user` DISABLE KEYS */;
INSERT INTO `series_user` VALUES (1,1,72,10,'2024-03-29 07:15:38'),(1,2,184,10,'2024-03-29 07:30:15'),(1,3,64,10,'2024-03-29 07:30:15'),(1,4,321,10,'2024-03-29 07:30:15'),(1,5,168,10,'2024-03-29 07:30:15'),(1,6,134,10,'2024-03-29 07:30:15'),(1,7,-55,10,'2024-03-29 07:30:15'),(1,8,-32,10,'2024-03-29 07:30:15'),(1,9,-51,10,'2024-03-29 07:30:15'),(1,10,-2,10,'2024-03-29 07:30:15'),(1,11,-379,10,'2024-03-29 07:30:15'),(1,12,220,10,'2024-03-29 07:30:15'),(1,13,-118,10,'2024-03-29 07:30:15'),(1,14,-126,10,'2024-03-29 07:30:15'),(1,15,106,10,'2024-03-29 07:30:15'),(1,16,-484,10,'2024-03-29 07:30:15');
/*!40000 ALTER TABLE `series_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `team`
--

DROP TABLE IF EXISTS `team`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `team` (
  `Team_Id` int NOT NULL AUTO_INCREMENT,
  `Team_Name` varchar(50) COLLATE utf8mb4_general_ci NOT NULL,
  `Team_Short_Name` varchar(3) COLLATE utf8mb4_general_ci NOT NULL,
  `Updated_By` int NOT NULL,
  `Updated_TS` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`Team_Id`),
  KEY `FK_Updated_By_Team` (`Updated_By`),
  CONSTRAINT `FK_Updated_By_Team` FOREIGN KEY (`Updated_By`) REFERENCES `user` (`User_Id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `team`
--

LOCK TABLES `team` WRITE;
/*!40000 ALTER TABLE `team` DISABLE KEYS */;
INSERT INTO `team` VALUES (1,'Chennai Super Kings','CSK',10,'2024-03-29 06:40:49'),(2,'Delhi Capitals','DC',10,'2024-03-29 06:41:14'),(3,'Gujarat Titans','GT',10,'2024-03-29 06:41:35'),(4,'Kolkata Knight Riders','KKR',10,'2024-03-29 06:42:27'),(5,'Lucknow Super Giants','LSG',10,'2024-03-29 06:42:55'),(6,'Mumbai Indians','MI',10,'2024-03-29 06:43:13'),(7,'Punjab Kings','PBK',10,'2024-03-29 06:43:37'),(8,'Rajasthan Royals','RR',10,'2024-03-29 06:43:55'),(9,'Royal Challengers Bangalore','RCB',10,'2024-03-29 06:44:18'),(10,'Sunrisers Hyderabad','SRH',10,'2024-03-29 06:44:34');
/*!40000 ALTER TABLE `team` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user` (
  `User_Id` int NOT NULL AUTO_INCREMENT,
  `User_Type` enum('A','U') COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'U',
  `Phone` varchar(50) COLLATE utf8mb4_general_ci NOT NULL,
  `Initial_Pass` varchar(15) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `Password` varchar(60) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `Name` varchar(58) COLLATE utf8mb4_general_ci NOT NULL,
  `Updated_By` int NOT NULL,
  `Updated_TS` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`User_Id`),
  UNIQUE KEY `Email_UNIQUE` (`Phone`),
  KEY `FK_Updated_By_User` (`Updated_By`),
  CONSTRAINT `FK_Updated_By_User` FOREIGN KEY (`Updated_By`) REFERENCES `user` (`User_Id`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'A','7827278998',NULL,'$2b$12$4PmhyXc2jz7jR8dWHyPmuOlUR2uH1nzcQ/JbQTygZvrO5/A3uiEni','Ravi',1,'2024-03-29 07:20:40'),(2,'A','9160022298',NULL,'$2b$12$zQ8AJWDMl2iQBv7H0fjwCeITqMvJ.8jjo8rMKEP0wFAGBwXGBbwg2','Keerti',1,'2024-03-29 07:21:37'),(3,'U','9701176548',NULL,'$2b$12$o/lxaLx6l67xcz941zu3vO2rsjV66bLVuDVwlnHkLFtQDPuOkD7Wy','Raju',1,'2024-03-29 07:22:13'),(4,'A','8886008619',NULL,'$2b$12$iV7FpZ.SHEwc.7eRf/DWH.sMgS1lQsDyt9cMnXSUREI2HMVOFtqFy','Venkat K',1,'2024-03-29 07:22:44'),(5,'A','9894870676',NULL,'$2b$12$9kZUmHRkMYGHw0owUmGbveOo9oGt5/Iyvdm1xatVDK8Y3.IFEqW16','Narasimman',1,'2024-03-29 07:23:21'),(6,'U','9032202464',NULL,'$2b$12$hf9pW/W4bYrEbXcfLGP2vu93RuwLuGQ0tscxD/RoWDA7cU6kqKpZC','Preeti Patil',1,'2024-03-29 07:24:14'),(7,'U','9493423191',NULL,'$2b$12$lB2GWlGfscphm6IvkKuT0O07/80LnpGhOesWMEzgQpR1IclCliUBW','Giri',1,'2024-03-29 07:24:39'),(8,'U','9666336044',NULL,'$2b$12$91aHiVGdHTkGN1hKQ1slaOsYDRrtummmrGvFDDvRW4/iljsczrcey','Kishore',1,'2024-03-29 07:25:06'),(9,'U','6383083116',NULL,'$2b$12$GesYvUzwoLgUtFloQ4rwJudtvZs.q3OVN/l21YEP4gACZtdrhVf1e','Hari',1,'2024-03-29 07:25:26'),(10,'A','8101042280',NULL,'$2b$12$kw4rgD3qgk9o0vhGKpGG3eE8TBD0wIqEU9jKMNvOa1jo3wGI2J/Ca','Avinash',1,'2024-03-29 06:11:46'),(11,'U','9989849376','udxh232b',NULL,'Kondal',1,'2024-03-29 07:25:57'),(12,'U','9971100851',NULL,'$2b$12$NugTiEERhZsVln1/acmcHureizMXq2j8CExf940yfILA3R.51rBBm','Vijay Gandhi',1,'2024-03-29 07:26:22'),(13,'U','9030777464',NULL,'$2b$12$9USrPkv1QVi1siEeejboCOhhwTXs7dhHuQlelu/ycFf0WeuyxOAtC','Madan',1,'2024-03-29 07:26:55'),(14,'U','9873384947',NULL,'$2b$12$oLKKTt1SXzmTlOx9xWcgaethOLiHP7nj0R23e3YAukZaJVk/Kj9oW','Abhishek',1,'2024-03-29 07:27:22'),(15,'U','9717877796',NULL,'$2b$12$Zbh1kZA9nEqzZzQCxBlMwODj..CAROiXtAZZwpqLpSchQfJR7Tqhu','Shivam',1,'2024-03-29 07:27:44'),(16,'U','9718313247',NULL,'$2b$12$xdgt3ChYuAD4m/UB.DYfyOhknWd450FSjM50O8hytcP39O.03M7mG','Himanshu',1,'2024-03-29 07:28:15');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-04-13  0:02:35
