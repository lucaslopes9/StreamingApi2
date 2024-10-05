<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
$lang = empty($_GET['lang']) ? "" : $_GET['lang'];
if(!empty($lang)) SalvarIdioma($lang);
global $_TRA;

$VerificarInfoSite = VerificarInfoSite();
if(ProtegePag() == true){
?>

<!DOCTYPE html>
<html lang="<?php echo $idioma; ?>">
    <head>        
        <!-- META SECTION -->
        <title><?php echo $VerificarInfoSite[0]; ?></title>            
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        
        <link rel="icon" href="favicon.ico" type="image/x-icon" />
        <!-- END META SECTION -->
        
        <!-- CSS INCLUDE -->        
        <link rel="stylesheet" type="text/css" id="theme" href="css/<?php echo $VerificarInfoSite[2]; ?>.css"/>
        <link rel="stylesheet" href="http://fontawesome.io/assets/font-awesome/css/font-awesome.css">
        <!-- EOF CSS INCLUDE -->         
                  
    </head>
    <body>
        <!-- START PAGE CONTAINER -->
        <div class="page-container">
       <?php
			include("menu.php");
			?> 
            <div class="page-content">
                
            <!-- MENU VERTICAL -->
            <?php
			include("menu-vertical.php");
			?>              
			<!-- END MENU VERTICAL -->
                        
                
            <!-- PAGINACAO -->
            <?php
		if (isset($_GET['p'])){
        	if (file_exists($_GET['p'] . ".php") && $_GET['p'] != 'index'){
        		include $_GET['p'] . ".php"; 
        	}
			else{
                include "error.php";
       		}
		}
		else{
       		include "inicio.php";
		}
				?>
                <!-- END PAGINACAO -->                                
            </div>            
            <!-- END PAGE CONTENT -->
        </div>
        
        <script type='text/javascript' src='js/plugins/noty/jquery.noty.js'></script>
        <script type='text/javascript' src='js/plugins/noty/layouts/topCenter.js'></script>
        <script type='text/javascript' src='js/plugins/noty/layouts/topLeft.js'></script>
        <script type='text/javascript' src='js/plugins/noty/layouts/topRight.js'></script>            
        <script type='text/javascript' src='js/plugins/noty/themes/default.js'></script>
        
        <script type='text/javascript'> 
        	<?php
				if(!empty($_SESSION['obs'])){
					
				$obs = str_replace("\n","<br>",$_SESSION['obs']);
				$obs = str_replace("\r","",$obs);
				?>
				notyConfirm();
				
				function notyConfirm(){
                    noty({
                        text: '<?php echo $obs; ?>',
                        layout: 'topRight',
                        buttons: [
                                {addClass: 'btn btn-success btn-clean', text: '<?php echo $_TRA['ok']; ?>', onClick: function($noty) {
                                    $noty.close();
                                    noty({text: '<?php echo $_TRA['oeansmens']; ?>', layout: 'topRight', type: 'success'});
									$.post('EnviarFecharAlerta.php');
                                }
                                },
                                {addClass: 'btn btn-danger btn-clean', text: '<?php echo $_TRA['fechar']; ?>', onClick: function($noty) {
                                    $noty.close();
                                 }
                                }
                            ]
                    })                                                    
                }      
				<?php
				}
				?>
				
				
		function EnviarCircular(){
			
				panel_refresh($(".page-container"));
 		
				$.post('ScriptModalEnviarCircular.php', function(resposta) {
					
					setTimeout(panel_refresh($(".page-container")),500);
					
					$("#StatusCircular").html('');
					$("#StatusCircular").html(resposta);
				});
				
		}
		
		<?php
		if(!empty($_SESSION['MensagemInterna'])){
		?>
		VerificarCircular();
		function VerificarCircular(){
			
				panel_refresh($(".page-container"));
 		
				$.post('ScriptModalCircular.php', function(resposta) {
					
					setTimeout(panel_refresh($(".page-container")),500);
					
					$("#StatusCircularExibir").html('');
					$("#StatusCircularExibir").html(resposta);
				});
				
		}
		<?php
		}
		?>	
        </script>
        
        <div id="StatusCircular"></div>
        <div id="StatusCircularExibir"></div>
                  
    </body>
</html>

<?php
}
else{
	echo Redirecionar('login.php');
}
?>




