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
INSERT INTO `match` VALUES (1,1,'2024-03-22 19:30:00','Chennai',1,9,'1',10,'2024-03-29 20:09:16'),(2,1,'2024-03-23 15:00:00','Mohali',7,2,'1',10,'2024-03-29 20:09:28'),(3,1,'2024-03-23 19:00:00','Kolkata',4,10,'1',10,'2024-03-29 20:09:36'),(4,1,'2024-03-24 15:00:00','Jaipur ',8,5,'1',10,'2024-03-29 20:15:11'),(5,1,'2024-03-24 19:00:00','Ahmedabad',3,6,'1',10,'2024-03-29 20:18:43'),(6,1,'2024-03-25 19:00:00','Bengaluru',9,7,'1',10,'2024-03-29 20:24:55'),(7,1,'2024-03-26 19:00:00','Chennai',1,3,'1',10,'2024-03-30 10:43:13'),(8,1,'2024-03-27 19:00:00','Hyderabad',10,6,'1',10,'2024-03-30 10:52:20'),(9,1,'2024-03-28 19:00:00','Jaipur',8,2,'1',10,'2024-03-30 10:56:10'),(10,1,'2024-03-29 19:00:00','Bengaluru',9,4,'2',10,'2024-03-31 06:32:08'),(11,1,'2024-03-30 19:00:00','Lucknow',5,7,'1',10,'2024-03-31 06:51:19'),(12,1,'2024-03-31 15:00:00','Ahmedabad',3,10,NULL,10,'2024-03-29 07:12:57'),(13,1,'2024-03-31 19:00:00','Visakhapatnam',2,1,NULL,10,'2024-03-29 07:12:57'),(14,1,'2024-04-01 19:00:00','Mumbai',6,8,NULL,10,'2024-03-29 07:12:57'),(15,1,'2024-04-02 19:00:00','Bengaluru',9,5,NULL,10,'2024-03-29 07:12:57'),(16,1,'2024-04-03 19:00:00','Visakhapatnam',2,4,NULL,10,'2024-03-29 07:12:57'),(17,1,'2024-04-04 19:00:00','Ahmedabad',3,7,NULL,10,'2024-03-29 07:12:57'),(18,1,'2024-04-05 19:00:00','Hyderabad',10,1,NULL,10,'2024-03-29 07:12:57'),(19,1,'2024-04-06 19:00:00','Jaipur',8,9,NULL,10,'2024-03-29 07:12:57'),(20,1,'2024-04-07 15:00:00','Mumbai',6,2,NULL,10,'2024-03-29 07:12:57'),(21,1,'2024-04-07 19:00:00','Lucknow',5,3,NULL,10,'2024-03-29 07:12:57'),(22,1,'2024-04-08 19:00:00','Chennai',1,4,NULL,10,'2024-03-29 07:12:57'),(23,1,'2024-04-09 19:00:00','Mohali',7,10,NULL,10,'2024-03-29 07:12:57'),(24,1,'2024-04-10 19:00:00','Jaipur',8,3,NULL,10,'2024-03-29 07:12:57'),(25,1,'2024-04-11 19:00:00','Mumbai',6,9,NULL,10,'2024-03-29 07:12:57'),(26,1,'2024-04-12 19:00:00','Lucknow',5,2,NULL,10,'2024-03-29 07:12:57'),(27,1,'2024-04-13 19:00:00','Mohali',7,8,NULL,10,'2024-03-29 07:12:57'),(28,1,'2024-04-14 15:00:00','Kolkata',4,5,NULL,10,'2024-03-29 07:12:57'),(29,1,'2024-04-14 19:00:00','Mumbai',6,1,NULL,10,'2024-03-29 07:12:57'),(30,1,'2024-04-15 19:00:00','Bengaluru',9,10,NULL,10,'2024-03-29 07:12:57'),(31,1,'2024-04-16 19:00:00','Ahmedabad',3,2,NULL,10,'2024-03-29 07:12:57'),(32,1,'2024-04-17 19:00:00','Kolkata',4,8,NULL,10,'2024-03-29 07:12:57'),(33,1,'2024-04-18 19:00:00','Mohali',7,6,NULL,10,'2024-03-29 07:12:57'),(34,1,'2024-04-19 19:00:00','Lucknow',5,1,NULL,10,'2024-03-29 07:12:57'),(35,1,'2024-04-20 19:00:00','Delhi',2,10,NULL,10,'2024-03-29 07:12:57'),(36,1,'2024-04-21 15:00:00','Kolkata',4,9,NULL,10,'2024-03-29 07:12:57'),(37,1,'2024-04-21 19:00:00','Mohali',7,3,NULL,10,'2024-03-29 07:12:57'),(38,1,'2024-04-22 19:00:00','Jaipur',8,6,NULL,10,'2024-03-29 07:12:57'),(39,1,'2024-04-23 19:00:00','Chennai',1,5,NULL,10,'2024-03-29 07:12:57'),(40,1,'2024-04-24 19:00:00','Delhi',2,3,NULL,10,'2024-03-29 07:12:57'),(41,1,'2024-04-25 19:00:00','Hyderabad',10,9,NULL,10,'2024-03-29 07:12:57'),(42,1,'2024-04-26 19:00:00','Kolkata',4,7,NULL,10,'2024-03-29 07:12:57'),(43,1,'2024-04-27 15:00:00','Delhi',2,6,NULL,10,'2024-03-29 07:12:57'),(44,1,'2024-04-27 19:00:00','Lucknow',5,8,NULL,10,'2024-03-29 07:12:57'),(45,1,'2024-04-28 19:00:00','Ahmedabad',3,9,NULL,10,'2024-03-29 07:12:57'),(46,1,'2024-04-28 19:00:00','Chennai',1,10,NULL,10,'2024-03-29 07:12:57'),(47,1,'2024-04-29 19:00:00','Kolkata',4,2,NULL,10,'2024-03-29 07:12:57'),(48,1,'2024-04-30 19:00:00','Lucknow',5,6,NULL,10,'2024-03-29 07:12:57'),(49,1,'2024-05-01 19:00:00','Chennai',1,7,NULL,10,'2024-03-29 07:12:57'),(50,1,'2024-05-02 19:00:00','Hyderabad',10,8,NULL,10,'2024-03-29 07:12:57'),(51,1,'2024-05-03 19:00:00','Mumbai',6,4,NULL,10,'2024-03-29 07:12:57'),(52,1,'2024-05-04 19:00:00','Bengaluru',9,3,NULL,10,'2024-03-29 07:12:57'),(53,1,'2024-05-05 15:00:00','Dharamshala',7,1,NULL,10,'2024-03-29 07:12:57'),(54,1,'2024-05-05 19:00:00','Lucknow',5,4,NULL,10,'2024-03-29 07:12:57'),(55,1,'2024-05-06 19:00:00','Mumbai',6,10,NULL,10,'2024-03-29 07:12:57'),(56,1,'2024-05-07 19:00:00','Delhi',2,8,NULL,10,'2024-03-29 07:12:57'),(57,1,'2024-05-08 19:00:00','Hyderabad',10,5,NULL,10,'2024-03-29 07:12:57'),(58,1,'2024-05-09 19:00:00','Dharamshala',7,9,NULL,10,'2024-03-29 07:12:57'),(59,1,'2024-05-10 19:00:00','Ahmedabad',3,1,NULL,10,'2024-03-29 07:12:57'),(60,1,'2024-05-11 19:00:00','Kolkata',4,6,NULL,10,'2024-03-29 07:12:57'),(61,1,'2024-05-12 15:00:00','Chennai',1,8,NULL,10,'2024-03-29 07:12:57'),(62,1,'2024-05-12 19:00:00','Bengaluru',9,2,NULL,10,'2024-03-29 07:12:57'),(63,1,'2024-05-13 19:00:00','Ahmedabad',3,4,NULL,10,'2024-03-29 07:12:57'),(64,1,'2024-05-14 19:00:00','Delhi',2,5,NULL,10,'2024-03-29 07:12:57'),(65,1,'2024-05-15 19:00:00','Guwahati',8,7,NULL,10,'2024-03-29 07:12:57'),(66,1,'2024-05-16 19:00:00','Hyderabad',10,3,NULL,10,'2024-03-29 07:12:57'),(67,1,'2024-05-17 19:00:00','Mumbai',6,5,NULL,10,'2024-03-29 07:12:57'),(68,1,'2024-05-18 19:00:00','Bengaluru',9,1,NULL,10,'2024-03-29 07:12:57'),(69,1,'2024-05-19 15:00:00','Hyderabad',10,7,NULL,10,'2024-03-29 07:12:57'),(70,1,'2024-05-19 19:00:00','Guwahati',8,4,NULL,10,'2024-03-29 07:12:57');
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
INSERT INTO `poll` VALUES (1,1,1,12,10,'2024-03-29 18:42:44'),(1,2,9,-20,10,'2024-03-29 18:55:07'),(1,3,9,-20,10,'2024-03-29 18:55:07'),(1,4,1,12,10,'2024-03-29 18:43:06'),(1,5,1,12,10,'2024-03-29 18:43:11'),(1,6,1,12,10,'2024-03-29 18:43:16'),(1,7,1,12,10,'2024-03-29 18:43:21'),(1,8,9,-20,10,'2024-03-29 18:55:07'),(1,9,1,12,10,'2024-03-29 18:43:35'),(1,10,1,12,10,'2024-03-29 18:43:40'),(1,11,NULL,-20,10,'2024-03-29 18:55:07'),(1,12,9,-20,10,'2024-03-29 18:55:07'),(1,13,1,12,10,'2024-03-29 18:43:56'),(1,14,1,12,10,'2024-03-29 18:44:02'),(1,15,1,12,10,'2024-03-29 18:44:10'),(1,16,9,-20,10,'2024-03-29 18:55:07'),(2,1,NULL,-20,10,'2024-03-29 19:05:12'),(2,2,7,26,10,'2024-03-29 19:00:06'),(2,3,7,26,10,'2024-03-29 19:00:19'),(2,4,NULL,-20,10,'2024-03-29 19:05:12'),(2,5,7,26,10,'2024-03-29 19:00:33'),(2,6,7,26,10,'2024-03-29 19:00:36'),(2,7,NULL,-20,10,'2024-03-29 19:05:12'),(2,8,7,26,10,'2024-03-29 19:00:48'),(2,9,NULL,-20,10,'2024-03-29 19:05:12'),(2,10,2,-20,10,'2024-03-29 19:01:40'),(2,11,NULL,-20,10,'2024-03-29 19:05:12'),(2,12,7,26,10,'2024-03-29 19:01:01'),(2,13,NULL,-20,10,'2024-03-29 19:05:12'),(2,14,7,26,10,'2024-03-29 19:01:14'),(2,15,NULL,-20,10,'2024-03-29 19:05:12'),(2,16,NULL,-20,10,'2024-03-29 19:05:12'),(3,1,4,16,10,'2024-03-29 19:59:56'),(3,2,4,16,10,'2024-03-29 20:00:07'),(3,3,NULL,-20,10,'2024-03-29 20:03:18'),(3,4,NULL,-20,10,'2024-03-29 20:03:18'),(3,5,NULL,-20,10,'2024-03-29 20:03:19'),(3,6,4,16,10,'2024-03-29 20:00:22'),(3,7,NULL,-20,10,'2024-03-29 20:03:19'),(3,8,4,16,10,'2024-03-29 20:00:35'),(3,9,4,16,10,'2024-03-29 20:00:40'),(3,10,4,16,10,'2024-03-29 20:00:45'),(3,11,NULL,-20,10,'2024-03-29 20:03:19'),(3,12,4,16,10,'2024-03-29 20:00:59'),(3,13,4,16,10,'2024-03-29 20:01:04'),(3,14,NULL,-20,10,'2024-03-29 20:03:19'),(3,15,NULL,-20,10,'2024-03-29 20:03:19'),(3,16,4,16,10,'2024-03-29 20:01:18'),(4,1,8,20,10,'2024-03-29 20:12:30'),(4,2,NULL,-20,10,'2024-03-29 20:15:11'),(4,3,NULL,-20,10,'2024-03-29 20:15:11'),(4,4,NULL,-20,10,'2024-03-29 20:15:11'),(4,5,8,20,10,'2024-03-29 20:12:40'),(4,6,8,20,10,'2024-03-29 20:12:47'),(4,7,8,20,10,'2024-03-29 20:12:53'),(4,8,8,20,10,'2024-03-29 20:12:58'),(4,9,NULL,-20,10,'2024-03-29 20:15:11'),(4,10,8,20,10,'2024-03-29 20:13:13'),(4,11,NULL,-20,10,'2024-03-29 20:15:11'),(4,12,8,20,10,'2024-03-29 20:13:33'),(4,13,NULL,-20,10,'2024-03-29 20:15:11'),(4,14,8,20,10,'2024-03-29 20:13:53'),(4,15,NULL,-20,10,'2024-03-29 20:15:11'),(4,16,NULL,-20,10,'2024-03-29 20:15:11'),(5,1,NULL,-20,10,'2024-03-29 20:18:43'),(5,2,NULL,-20,10,'2024-03-29 20:18:43'),(5,3,NULL,-20,10,'2024-03-29 20:18:43'),(5,4,3,60,10,'2024-03-29 20:16:55'),(5,5,3,60,10,'2024-03-29 20:17:03'),(5,6,NULL,-20,10,'2024-03-29 20:18:43'),(5,7,NULL,-20,10,'2024-03-29 20:18:43'),(5,8,NULL,-20,10,'2024-03-29 20:18:43'),(5,9,NULL,-20,10,'2024-03-29 20:18:43'),(5,10,NULL,-20,10,'2024-03-29 20:18:43'),(5,11,NULL,-20,10,'2024-03-29 20:18:43'),(5,12,3,60,10,'2024-03-29 20:17:25'),(5,13,NULL,-20,10,'2024-03-29 20:18:43'),(5,14,NULL,-20,10,'2024-03-29 20:18:43'),(5,15,3,60,10,'2024-03-29 20:17:32'),(5,16,NULL,-20,10,'2024-03-29 20:18:43'),(6,1,9,16,10,'2024-03-29 20:22:33'),(6,2,NULL,-20,10,'2024-03-29 20:24:55'),(6,3,9,16,10,'2024-03-29 20:22:45'),(6,4,NULL,-20,10,'2024-03-29 20:24:55'),(6,5,NULL,-20,10,'2024-03-29 20:24:55'),(6,6,9,16,10,'2024-03-29 20:22:53'),(6,7,9,16,10,'2024-03-29 20:22:58'),(6,8,NULL,-20,10,'2024-03-29 20:24:55'),(6,9,9,16,10,'2024-03-29 20:23:15'),(6,10,NULL,-20,10,'2024-03-29 20:24:55'),(6,11,9,16,10,'2024-03-29 20:23:21'),(6,12,9,16,10,'2024-03-29 20:23:28'),(6,13,NULL,-20,10,'2024-03-29 20:24:55'),(6,14,9,16,10,'2024-03-29 20:23:50'),(6,15,9,16,10,'2024-03-29 20:23:56'),(6,16,NULL,-20,10,'2024-03-29 20:24:55'),(7,1,NULL,-20,10,'2024-03-30 10:43:13'),(7,2,NULL,-20,10,'2024-03-30 10:43:13'),(7,3,1,16,10,'2024-03-30 10:40:54'),(7,4,1,16,10,'2024-03-30 10:40:59'),(7,5,1,16,10,'2024-03-30 10:41:05'),(7,6,1,16,10,'2024-03-30 10:41:09'),(7,7,1,16,10,'2024-03-30 10:41:14'),(7,8,NULL,-20,10,'2024-03-30 10:43:13'),(7,9,1,16,10,'2024-03-30 10:41:28'),(7,10,1,16,10,'2024-03-30 10:41:33'),(7,11,1,16,10,'2024-03-30 10:41:38'),(7,12,NULL,-20,10,'2024-03-30 10:43:13'),(7,13,NULL,-20,10,'2024-03-30 10:43:13'),(7,14,1,16,10,'2024-03-30 10:41:55'),(7,15,NULL,-20,10,'2024-03-30 10:43:13'),(7,16,NULL,-20,10,'2024-03-30 10:43:13'),(8,1,NULL,-20,10,'2024-03-30 10:52:20'),(8,2,NULL,-20,10,'2024-03-30 10:52:20'),(8,3,10,26,10,'2024-03-30 10:49:09'),(8,4,10,26,10,'2024-03-30 10:49:13'),(8,5,10,26,10,'2024-03-30 10:49:18'),(8,6,10,26,10,'2024-03-30 10:49:23'),(8,7,10,26,10,'2024-03-30 10:49:27'),(8,8,NULL,-20,10,'2024-03-30 10:52:20'),(8,9,10,26,10,'2024-03-30 10:50:10'),(8,10,NULL,-20,10,'2024-03-30 10:52:20'),(8,11,NULL,-20,10,'2024-03-30 10:52:20'),(8,12,10,26,10,'2024-03-30 10:50:23'),(8,13,NULL,-20,10,'2024-03-30 10:52:20'),(8,14,NULL,-20,10,'2024-03-30 10:52:20'),(8,15,NULL,-20,10,'2024-03-30 10:52:20'),(8,16,NULL,-20,10,'2024-03-30 10:52:20'),(9,1,8,9,10,'2024-03-30 10:53:46'),(9,2,NULL,-20,10,'2024-03-30 10:56:10'),(9,3,8,9,10,'2024-03-30 10:53:52'),(9,4,NULL,-20,10,'2024-03-30 10:56:10'),(9,5,8,9,10,'2024-03-30 10:53:57'),(9,6,8,9,10,'2024-03-30 10:54:02'),(9,7,8,9,10,'2024-03-30 10:54:08'),(9,8,8,9,10,'2024-03-30 10:54:28'),(9,9,8,9,10,'2024-03-30 10:54:32'),(9,10,NULL,-20,10,'2024-03-30 10:56:10'),(9,11,8,9,10,'2024-03-30 10:54:49'),(9,12,NULL,-20,10,'2024-03-30 10:56:10'),(9,13,8,9,10,'2024-03-30 10:54:55'),(9,14,8,9,10,'2024-03-30 10:54:58'),(9,15,8,9,10,'2024-03-30 10:55:02'),(9,16,NULL,-20,10,'2024-03-30 10:56:10'),(10,1,4,26,10,'2024-03-31 06:26:43'),(10,2,9,-20,10,'2024-03-31 06:27:51'),(10,3,9,-20,10,'2024-03-31 06:28:05'),(10,4,4,26,10,'2024-03-31 06:25:18'),(10,5,9,-20,10,'2024-03-31 06:27:18'),(10,6,4,26,10,'2024-03-31 06:26:27'),(10,7,4,26,10,'2024-03-31 06:25:44'),(10,8,NULL,-20,10,'2024-03-31 06:32:09'),(10,9,4,26,10,'2024-03-31 06:25:26'),(10,10,9,-20,10,'2024-03-31 06:27:36'),(10,11,9,-20,10,'2024-03-31 06:28:15'),(10,12,9,-20,10,'2024-03-31 06:27:26'),(10,13,9,-20,10,'2024-03-31 06:28:20'),(10,14,4,26,10,'2024-03-31 06:26:08'),(10,15,4,26,10,'2024-03-31 06:26:01'),(10,16,NULL,-20,10,'2024-03-31 06:32:09'),(11,1,5,20,10,'2024-03-31 06:38:23'),(11,2,7,-20,10,'2024-03-31 06:41:29'),(11,3,5,20,10,'2024-03-31 06:39:48'),(11,4,5,20,10,'2024-03-31 06:39:53'),(11,5,7,-20,10,'2024-03-31 06:42:15'),(11,6,7,-20,10,'2024-03-31 06:42:23'),(11,7,7,-20,10,'2024-03-31 06:42:28'),(11,8,5,20,10,'2024-03-31 06:40:02'),(11,9,5,20,10,'2024-03-31 06:38:43'),(11,10,7,-20,10,'2024-03-31 06:41:48'),(11,11,5,20,10,'2024-03-31 06:39:18'),(11,12,7,-20,10,'2024-03-31 06:41:39'),(11,13,7,-20,10,'2024-03-31 06:42:35'),(11,14,5,20,10,'2024-03-31 06:39:05'),(11,15,5,20,10,'2024-03-31 06:38:59'),(11,16,NULL,-20,10,'2024-03-31 06:51:19'),(12,1,10,NULL,10,'2024-03-31 11:32:06'),(12,2,3,NULL,10,'2024-03-31 11:31:01'),(12,3,10,NULL,10,'2024-03-31 11:33:09'),(12,4,10,NULL,10,'2024-03-31 11:33:15'),(12,5,10,NULL,10,'2024-03-31 11:32:17'),(12,6,10,NULL,10,'2024-03-31 11:33:21'),(12,7,10,NULL,10,'2024-03-31 11:33:26'),(12,8,10,NULL,10,'2024-03-31 11:33:32'),(12,9,10,NULL,10,'2024-03-31 11:32:36'),(12,10,3,NULL,10,'2024-03-31 11:30:32'),(12,11,10,NULL,10,'2024-03-31 11:32:26'),(12,12,3,NULL,10,'2024-03-31 11:31:11'),(12,13,3,NULL,10,'2024-03-31 11:31:17'),(12,14,3,NULL,10,'2024-03-31 11:31:29'),(12,15,3,NULL,10,'2024-03-31 11:31:35'),(13,1,1,NULL,10,'2024-03-31 11:38:14'),(13,2,2,NULL,10,'2024-03-31 11:37:13'),(13,3,1,NULL,10,'2024-03-31 11:38:21'),(13,4,2,NULL,10,'2024-03-31 11:37:20'),(13,5,1,NULL,10,'2024-03-31 11:38:40'),(13,6,1,NULL,10,'2024-03-31 11:38:45'),(13,7,1,NULL,10,'2024-03-31 11:38:49'),(13,8,1,NULL,10,'2024-03-31 11:38:54'),(13,9,1,NULL,10,'2024-03-31 11:38:58'),(13,10,1,NULL,10,'2024-03-31 11:36:46'),(13,11,1,NULL,10,'2024-03-31 11:39:03'),(13,12,2,NULL,10,'2024-03-31 11:37:37'),(13,13,1,NULL,10,'2024-03-31 11:39:08'),(13,14,1,NULL,10,'2024-03-31 11:39:12'),(13,15,1,NULL,10,'2024-03-31 11:39:17');
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
INSERT INTO `series_user` VALUES (1,1,39,10,'2024-03-29 07:15:38'),(1,2,-138,10,'2024-03-29 07:30:15'),(1,3,13,10,'2024-03-29 07:30:15'),(1,4,60,10,'2024-03-29 07:30:15'),(1,5,89,10,'2024-03-29 07:30:15'),(1,6,127,10,'2024-03-29 07:30:15'),(1,7,45,10,'2024-03-29 07:30:15'),(1,8,-29,10,'2024-03-29 07:30:15'),(1,9,81,10,'2024-03-29 07:30:15'),(1,10,-76,10,'2024-03-29 07:30:15'),(1,11,-79,10,'2024-03-29 07:30:15'),(1,12,64,10,'2024-03-29 07:30:15'),(1,13,-123,10,'2024-03-29 07:30:15'),(1,14,85,10,'2024-03-29 07:30:15'),(1,15,43,10,'2024-03-29 07:30:15'),(1,16,-184,10,'2024-03-29 07:30:15');
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
  `Email` varchar(50) COLLATE utf8mb4_general_ci NOT NULL,
  `Initial_Pass` varchar(15) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `Password` varchar(60) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `Name` varchar(58) COLLATE utf8mb4_general_ci NOT NULL,
  `Updated_By` int NOT NULL,
  `Updated_TS` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`User_Id`),
  UNIQUE KEY `Email_UNIQUE` (`Email`),
  KEY `FK_Updated_By_User` (`Updated_By`),
  CONSTRAINT `FK_Updated_By_User` FOREIGN KEY (`Updated_By`) REFERENCES `user` (`User_Id`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'A','ravi@testmail.com','uhsdu327',NULL,'Ravi',1,'2024-03-29 07:20:40'),(2,'A','keerti@testmail.com','sdkjhfue',NULL,'Keerti',1,'2024-03-29 07:21:37'),(3,'U','raju@testmail.com','dsjhfu3y',NULL,'Raju',1,'2024-03-29 07:22:13'),(4,'A','venkat@testmail.com','sjfdiu3r',NULL,'Venkat K',1,'2024-03-29 07:22:44'),(5,'A','narasimman@testmail.com','jadhu2y8',NULL,'Narasimman',1,'2024-03-29 07:23:21'),(6,'U','preeti@testmail.com','sjh37y73',NULL,'Preeti Patil',1,'2024-03-29 07:24:14'),(7,'U','giri@testmail.com','87r3fhu8',NULL,'Giri',1,'2024-03-29 07:24:39'),(8,'U','kishore@testmail.com','uwh32732',NULL,'Kishore',1,'2024-03-29 07:25:06'),(9,'U','hari@testmail.com','238yugih',NULL,'Hari',1,'2024-03-29 07:25:26'),(10,'A','avin.asansol@gmail.com',NULL,'$2b$12$rTyUUHmZRz5owq4EP/IvpehpGhm1ZWWVs4BV2CgJf6ZGrm7IbSQSq','Avinash',1,'2024-03-29 06:11:46'),(11,'U','kondal@testmail.com','udxh232b',NULL,'Kondal',1,'2024-03-29 07:25:57'),(12,'U','vijay@testmail.com','832udhh2',NULL,'Vijay Gandhi',1,'2024-03-29 07:26:22'),(13,'U','madan@testmail.com','37yfd29',NULL,'Madan',1,'2024-03-29 07:26:55'),(14,'U','abhishek@testmail.com','328e7ttd',NULL,'Abhishek',1,'2024-03-29 07:27:22'),(15,'U','shivam@testmail.com','83gydy29',NULL,'Shivam',1,'2024-03-29 07:27:44'),(16,'U','himanshu@testmail.com','27yyd170',NULL,'Himanshu',1,'2024-03-29 07:28:15');
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

-- Dump completed on 2024-03-31 11:55:11
