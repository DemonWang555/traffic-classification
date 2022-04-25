# -----------------------------------------------------------------------
# database flowlog
# -----------------------------------------------------------------------
DROP DATABASE IF EXISTS flowlog;

CREATE DATABASE flowlog;
USE flowlog;

# -----------------------------------------------------------------------
# flow_properties table
# -----------------------------------------------------------------------
DROP TABLE IF EXISTS flow_properties;
CREATE TABLE flow_properties (
  tid  int unsigned NOT NULL auto_increment,
  src_IP varchar(16) default NULL,
  src_port int unsigned default 0,
  dst_IP varchar(16) default NULL,
  dst_port int unsigned default 0,
  protocol varchar(8) default NULL,
  Sid varchar(32) default NULL,
  description varchar(128) default NULL,
  timestamp datetime default NULL,
  PRIMARY KEY (tid)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

