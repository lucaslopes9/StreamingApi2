<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$Coluna_1 = array('AdminVisualizar');
$VerificarAcesso_1 = VerificarAcesso('admin', $Coluna_1);
$AdminVisualizar = $VerificarAcesso_1[0];

$Coluna_8 = array('RevVisualizar');
$VerificarAcesso_8 = VerificarAcesso('rev', $Coluna_8);
$RevVisualizar = $VerificarAcesso_8[0];
	
$Coluna_9 = array('UserVisualizar');
$VerificarAcesso_9 = VerificarAcesso('user', $Coluna_9);
$UserVisualizar = $VerificarAcesso_9[0];
	
$Coluna_10 = array('TesteVisualizar');
$VerificarAcesso_10 = VerificarAcesso('teste', $Coluna_10);
$TesteVisualizar = $VerificarAcesso_10[0];

if( ($AdminVisualizar == 'S') || ($RevVisualizar == 'S') || ($UserVisualizar == 'S') || ($TesteVisualizar == 'S') ){ 
	
$status = empty($_GET['s']) ? 0 : $_GET['s'];

//Usuário
$CadUser = InfoUser(2);
$DataTablesPost = "grupos-processo";
$DataTablesTargets = "{\"targets\": 0,\"orderable\": false}, {\"targets\": 1,\"orderable\": false}, {\"targets\": 10,\"orderable\": false}";
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['grupo']; ?></li>
                    <li class="active">Todos</li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-user"></span> Todos</h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default">
                                <div class="panel-heading">
    
    <div class="row">             
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
    <button type="button" class="btn btn-default"><span value="Todos" id="StatusUE"><?php echo $_TRA['Exibir']; ?></span></button>
    <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
     <ul class="dropdown-menu" role="menu">
     <?php
     echo SelecionarExibirAll($CadUser);
	 ?>
     </ul>
     &nbsp;&nbsp; 
    </div>
    
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
    <button type="button" class="btn btn-default"><span value="Todos" id="StatusE"><?php echo $_TRA['Status']; ?></span></button>
    <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
     <ul class="dropdown-menu" role="menu">
     <li><a status="Todos" class="ExibirStatus pointer"><?php echo $_TRA['Todos']; ?></a></li>
     <li><a status="Ativos" class="ExibirStatus pointer"><?php echo $_TRA['Ativos']; ?></a></li>
     <li><a status="Bloqueados" class="ExibirStatus pointer"><?php echo $_TRA['Bloqueados']; ?></a></li>
     <li><a status="Esgotados" class="ExibirStatus pointer"><?php echo $_TRA['Esgotados']; ?></a></li>
     </ul>
     &nbsp;&nbsp; 
    </div>
    
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
    <button type="button" class="btn btn-default"><span value="Todos" id="StatusP"><?php echo $_TRA['Perfil']; ?></span></button>
    <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="caret"></span></button>
     <ul class="dropdown-menu" role="menu">
     <?php echo PerfilSelect($CadUser); ?>
     </ul>
     &nbsp;&nbsp; 
    </div>
    
    <div class="ExibirAllOpcoes btn-group" style="padding:5px 0px 5px 0px;"></div>
    </div>
                                    
    <div class="row">                            
    <div class="btn-group col-md-3" style="padding:5px 0px 5px 0px;">    
                          
    <div class="input-group date">
    	<input type="text" id="PesquisaEntreData" name="PesquisaEntreData" class="form-control"/>
        <span class="input-group-addon"><span class="glyphicon glyphicon-calendar"></span></span>
    </div>
	</div>
    
    <div class="btn-group" style="padding:5px 0px 5px 5px;">                         
    <button type="button" class="ExibirPorData btn btn-success">Exibir por Data</button>
    </div>
    </div> 

                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                <div class="panel-body">
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th>Grupo</th>
                                    	<th><?php echo $_TRA['foto']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['user']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['email']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['conexao']; ?></th>
                                        <th><?php echo $_TRA['DataPremio']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
										<th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                               	<tr style="height: auto;"></tr>
                                </tbody>
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        
    

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->
        
        <script type="text/javascript" src="js/moment.min.js"></script>
        
        <script type="text/javascript" src="js/daterangepicker.js"></script>
        <link rel="stylesheet" type="text/css" href="css/daterangepicker.css" />

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <?php 
		
		if(empty($status)){
			include_once("js/DataTablesPost".Idioma(2).".php");
		}
		else{
		?>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        <?php
		}
		
		?>
                
        <script type='text/javascript'>  
		$(function() {
			$('input[name="PesquisaEntreData"]').daterangepicker({
				locale: {
      				format: 'DD/MM/YYYY'
    			}
			});
		});
			
		$(function(){  
 			$("button.ExibirPorData").click(function() {
				
				var PesquisaEntreData = $('.input-group input[name="PesquisaEntreData"]').val();
				var usuario = $('#StatusUE').attr('value');
								
				if(status == 'Todos'){
					usuarioE = '<?php echo $_TRA['Todos']; ?>';
				}
				else{
					usuarioE = usuario;
				}
				
				$("#StatusUE").html(usuarioE);

				$("#StatusUE").attr('value', usuario);
				
				var status = $('#StatusE').attr('value');
				var perfil = $('#StatusP').attr('value');
					
				var panel = $('.PanelStatus');
       		    panel_refresh(panel);
		
				$.post('grupos-status-entre-datas.php', {usuario: usuario, status: status, perfil: perfil, PesquisaEntreData: PesquisaEntreData}, function(resposta) {
					
					setTimeout(function(){
            			panel_refresh(panel);
        			},500);	

					$(".table-responsive").html('');
				    $(".table-responsive").html(resposta);
					
				});
			});
		});
		
		$(function(){  
 			$("a.Exibir").click(function() { 
				$(".ExibirAllOpcoes").html('');
 			
				var usuario = $(this).attr("usuario"); 
				
				if(status == 'Todos'){
					usuarioE = '<?php echo $_TRA['Todos']; ?>';
				}
				else{
					usuarioE = usuario;
				}
				
				$("#StatusUE").html(usuarioE);

				$("#StatusUE").attr('value', usuario);
				
				var status = $('#StatusE').attr('value');
				var perfil = $('#StatusP').attr('value');
				
				$.post('grupos-status.php', {usuario: usuario, status: status, perfil: perfil}, function(resposta) {
					
				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
				});
				
				
			});
		});
		
		$(function(){  
 			$("a.ExibirStatus").click(function() { 
 				$(".ExibirAllOpcoes").html('');
				
				var status = $(this).attr("status"); 
				
				if(status == 'Todos'){
					statusE = '<?php echo $_TRA['Todos']; ?>';
				}
				else if(status == 'Ativos'){
					statusE = '<?php echo $_TRA['Ativos']; ?>';
				}
				else if(status == 'Bloqueados'){
					statusE = '<?php echo $_TRA['Bloqueados']; ?>';
				}
				else if(status == 'Esgotados'){
					statusE = '<?php echo $_TRA['Esgotados']; ?>';
				}
				else{
					statusE = '<?php echo $_TRA['Todos']; ?>';
				}
				
				$("#StatusE").html(statusE);
				$("#StatusE").attr('value', status);
				
				var usuario = $('#StatusUE').attr('value');
				var perfil = $('#StatusP').attr('value');
				
				$.post('grupos-status.php', {usuario: usuario, status: status, perfil: perfil}, function(resposta) {
					
				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
				});
								
			});
		});
		
		
		$(function(){  
 			$("a.ExibirPerfil").click(function() { 
 				$(".ExibirAllOpcoes").html('');
				
				var perfil = $(this).attr("perfil"); 
				var nome = $(this).attr("nome"); 
				
				$("#StatusP").html(nome);
				$("#StatusP").attr('value', perfil);
				
				var usuario = $('#StatusUE').attr('value');
				var status = $('#StatusE').attr('value');
								
				$.post('grupos-status.php', {usuario: usuario, status: status, perfil: perfil}, function(resposta) {

				$(".table-responsive").html('');
				$(".table-responsive").html(resposta);
				});
								
			});
		});
	
		</script>
          

    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>