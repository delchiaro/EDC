<?php
/**************************************************************/
/*                        EIBnetmux webmon                    */
/*             Copyright (C) 2006-2009 by Urs Zurbuchen       */
/*                                                            */
/**************************************************************/


/**************************************************************/
/* deteremine our location in the file system                 */
/**************************************************************/
$webmonBasePath = str_replace( "\\", "/", dirname(__FILE__) ) . "/";

/**************************************************************/
/* load required files                                        */
/**************************************************************/
require_once( $webmonBasePath . "/config.php" );
require_once( "eibnetmux.php" );

/**************************************************************/
/* execute on commands                                        */
/**************************************************************/

if( isset( $_SERVER['HTTP_REFERER'] )) {
	$referrer = $_SERVER['HTTP_REFERER'];
} else {
	$referrer = "status.php";
}

if( isset( $_GET['s'] )) {
	$server = $_GET['s'];
} else {
	$server = 0;
}

$conn = new eibnetmux( "webmon", $configEibNetMuxConnection[$server]['host'], $configEibNetMuxConnection[$server]['port'] );

if( isset( $_GET['c'] )) {
	$state = ($_GET['c'] == 1) ? 1 : 0;
	$status = $conn->mgmt_connect( $state );
}

if( isset( $_GET['l'] )) {
	$result = $conn->mgmt_getloglevel();
	if( $result['status'] == 0 ) {
		$level = $result['level'];
	} else {
		$level = 0;
	}
	if( $_GET['l'] == 1 ) {
		$level = 2 * $level +1;
	} else {
		$level = ($level +1) / 2 -1;
	}
	$level = min( $level, 4096 );
	$level = max( $level, 0 );
	$status = $conn->mgmt_setloglevel( $level );
}
$conn->close();

/**************************************************************/
/* redirect back to referrer                                  */
/**************************************************************/
header( "Location: " . $referrer, TRUE, 302 );

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<!--
/**************************************************************/
/*                        EIBnetmux webmon                    */
/*             Copyright (C) 2006-2009 by Urs Zurbuchen       */
/*                                                            */
/**************************************************************/
-->
<html xmlns="http://www.w3.org/1999/xhtml"><head>
  <title>EIBnetmux webmon</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link rel="icon" href="./favicon.ico" type="image/x-icon" />
  <link rel="shortcut icon" href="./favicon.ico" type="image/x-icon" />
  <link rel="stylesheet" href="./eibnetmux.css" type="text/css" />
  <meta name="author" content="Urs Zurbuchen" />
  <meta http-equiv="Pragma" content="no-cache" />
  <script type="text/javascript" src="./browser.js"></script>
</head>
<body id="eibnetmuxBody">
<div id="header">
  <span id="logo"><img alt="eibnetmux logo" src="./eibnetmux_logo.png" height="55" /></span>
    <span id="browser_warning"><a href="http://getfirefox.com/" title="Get Firefox - Take Back the Web">
    <img class="firefox" src="http://www.mozilla.org/products/firefox/buttons/getfirefox_88x31.png" width="88" height="31" border="0" alt="Get Firefox" />
    </a>
    You really should upgrade to Firefox. Even this simple page is not rendered correctly by Internet Explorer.
    </span>
</div>
<script type="text/javascript">
    function get_element(id) {
        if (typeof id != 'string') return id;
        if (document.getElementById)
            return document.getElementById(id);
        if (document.all)
            return document.all[id];
        return null;
    }

    var e;
    if (document.getElementById)
        e = document.getElementById("browser_warning");
    if( e ) {
        e.style.visibility = 'hidden';
        if( browser.is_ie && browser.v_ie < 7 ) {
            e.style.visibility = 'visible';
        }
    }
</script>

<div id="menu">
  <p class="title">WebMon</p>
  <p class="item"><a href="status.php">Status</a></p>
  <p class="item"><a href="mgmt_connect.php?l=1">Increase log level</a></p>
  <p class="item"><a href="mgmt_connect.php?l=0">Decrease log level</a></p>
  <?php if( $status['value']['client']['active'] == 1 ) { ?>
  <p class="item"><a href="mgmt_connect.php?c=0">Disconnect from bus</a></p>
  <?php } else { ?>
  <p class="item"><a href="mgmt_connect.php?c=1">Connect to bus</a></p>
  <?php } ?>
</div>

<div id="contents">
  <div class="title">Browser strangeness encountered</div>
    <p class="text">You are using a strangely configured browser.
    You should have automatically been redirected to:
    <a href="<?php echo $referrer; ?>"><?php echo $referrer; ?></a>.</p>
</div>

</body>
</html>
