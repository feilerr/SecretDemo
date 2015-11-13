//
//  REMainViewController.m
//  RSA Example
//
//  Created by JS Lim on 1/7/14.
//  Copyright (c) 2014 JS Lim. All rights reserved.
//

#import "JSRSA.h"
#import "AA3DESManager.h"
#import "REMainViewController.h"
#import "AFNetworking.h"

// the cipherText is encrypted from plainText (83 characters) value
static NSString *plainText = @"hello world";

static NSString *publicEncryptedText = @"";
static NSString *privateEncryptedText = @"";
static NSString *URL1=@"http://192.168.1.97/u_zone_app_api/encryption/step1.php";
static NSString *URL2=@"http://192.168.1.97/u_zone_app_api/app/v1.5/user/test";

@interface REMainViewController ()

@property (nonatomic,strong)NSString *uuid;
@property (nonatomic,strong)NSString *en_username;

@property (nonatomic, strong) UIScrollView *scrollView;

// public encrypt - encrypt plain text using public key
@property (nonatomic, strong) UITextView *publicEncryptInputTextView;
@property (nonatomic, strong) UITextView *publicEncryptOutputTextView;
@property (nonatomic, strong) UIButton *publicEncryptButton;

// private decrypt - decrypt cipher text using private key
@property (nonatomic, strong) UITextView *privateDecryptInputTextView;
@property (nonatomic, strong) UITextView *privateDecryptOutputTextView;
@property (nonatomic, strong) UIButton *privateDecryptButton;

// private encrypt - encrypt plain text using private key
@property (nonatomic, strong) UITextView *privateEncryptInputTextView;
@property (nonatomic, strong) UITextView *privateEncryptOutputTextView;
@property (nonatomic, strong) UIButton *privateEncryptButton;

// public decrypt - decrypt cipher text using public key
@property (nonatomic, strong) UITextView *publicDecryptInputTextView;
@property (nonatomic, strong) UITextView *publicDecryptOutputTextView;
@property (nonatomic, strong) UIButton *publicDecryptButton;

@end

@implementation REMainViewController {
    UIView *_dummyView;
    NSLayoutConstraint *_dummyViewHeightConstraint;
    
    NSArray *textViews, *labels, *buttons;
    NSString *num1;
}

-(void)DEStest{
     //GIvbEJeibwY= , 7ZGvYcyYlZ8=
    NSString *key=@"111222";
    NSString *ivString=@"aabbccdd";
    NSString *beMakeString = @"333";
    NSString *encrypptString = [AA3DESManager getEncryptWithString:beMakeString keyString:key ivString:ivString];
    NSString *decryptString = [AA3DESManager getDecryptWithString:encrypptString keyString:key ivString:ivString];
    NSLog(@"3des加密:%@",encrypptString);
    NSLog(@"3des解密:%@",decryptString);
   
}

-(NSString *)subString:(NSString *)source length:(int)len{
    source=[source substringToIndex:len];
    return source;
}

- (NSString *)getSha256String:(NSString *)srcString{
    const char *cstr = [srcString UTF8String];
    //使用对应的CC_SHA1,CC_SHA256,CC_SHA384,CC_SHA512的长度分别是20,32,48,64
    unsigned char digest[32];
    //使用对应的CC_SHA256,CC_SHA384,CC_SHA512
    CC_SHA256(cstr,  strlen(cstr), digest);
    NSMutableString* result = [NSMutableString stringWithCapacity:32 * 2];
    for(int i = 0; i < 32; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

+ (NSDictionary *)dictionaryWithJsonString:(NSString *)jsonString {
    if (jsonString == nil) {
        return nil;
    }
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                        options:NSJSONReadingMutableContainers
                                                          error:&err];
    if(err) {
        NSLog(@"json解析失败：%@",err);
        return nil;
    }
    return dic;
}

-(void)firstPost:(NSString *)url params:(NSDictionary *)dict{
    
    AFHTTPRequestOperationManager *manager = [AFHTTPRequestOperationManager manager];
    
    // 设置请求格式
//    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    // 设置返回格式
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];

    [manager POST:url parameters:dict success: ^(AFHTTPRequestOperation *operation, id responseObject) {
        NSString *result = [[NSString alloc] initWithData:responseObject  encoding:NSUTF8StringEncoding];
        NSLog(@"%@",result);
        NSDictionary *dic=[self dictionaryWithJsonString:result];
        self.uuid=[[dic objectForKey:@"data"] objectForKey:@"uuid"];
        NSString *num2=[[dic objectForKey:@"data"] objectForKey:@"num2"];
        int tailor=[[[dic objectForKey:@"data"] objectForKey:@"tailor"] intValue];
        num2=[self subString:num2 length:tailor];
        NSString *num3=@"33333333";
        //客户端再生成随机数 num3,并组合成3DES加密公钥 s_key
        NSString *s_key=[NSString stringWithFormat:@"%@,%@,%@",num1,num2,num3];
        
        //对num3进行RSA加密
        NSString *en_num3=[[JSRSA sharedInstance] publicEncrypt:num3];
        NSString *username=@"male";
        
        //3des
        NSString *key=s_key;
        NSString *ivString=@"aabbccdd";
        NSString *beMakeString = username;
        //对username进行3DES加密
        self.en_username = [AA3DESManager getEncryptWithString:beMakeString keyString:key ivString:ivString];

        NSString *validation=[NSString stringWithFormat:@"%@,%@",num1,en_num3];
        validation=[self getSha256String:validation];
        
        //首次握手
        NSDictionary *firstHandle=[NSDictionary dictionaryWithObjectsAndKeys:en_num3,@"en_num3",validation,@"validation",self.uuid,@"uuid", nil];
        [self SecondPost:URL2 params:firstHandle];
    } failure: ^(AFHTTPRequestOperation *operation, NSError *error) {
        NSLog(@"错误:%@",error);
    }];

}

-(void)SecondPost:(NSString *)url params:(NSDictionary *)dict{
    AFHTTPRequestOperationManager *manager = [AFHTTPRequestOperationManager manager];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager POST:url parameters:dict success: ^(AFHTTPRequestOperation *operation, id responseObject) {
        NSString *result = [[NSString alloc] initWithData:responseObject  encoding:NSUTF8StringEncoding];
        NSDictionary *dic=[self dictionaryWithJsonString:result];
        if ([dic objectForKey:@"code"]!=nil) {
            int code=[[dic objectForKey:@"code"] intValue];
            if (code==205) {
                
                NSDictionary *thirdDic=[NSDictionary dictionaryWithObjectsAndKeys:self.uuid,@"uuid",self.en_username,@"username", nil];
                NSLog(@"通讯参数：%@",thirdDic);
                [self ThirdPost:URL2 params:thirdDic];
            }
        }
        NSLog(@"%@",result);
    } failure: ^(AFHTTPRequestOperation *operation, NSError *error) {
        
    }];
}

#pragma mark 传输
-(void)ThirdPost:(NSString *)url params:(NSDictionary *)dict{
    AFHTTPRequestOperationManager *manager = [AFHTTPRequestOperationManager manager];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager POST:url parameters:dict success: ^(AFHTTPRequestOperation *operation, id responseObject) {
        NSString *result = [[NSString alloc] initWithData:responseObject  encoding:NSUTF8StringEncoding];
        NSLog(@"通讯结果：%@",result);
    } failure: ^(AFHTTPRequestOperation *operation, NSError *error) {
        
    }];
}

- (NSDictionary *)dictionaryWithJsonString:(NSString *)jsonString {
    if (jsonString == nil) {
        return nil;
    }
    
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                        options:NSJSONReadingMutableContainers
                                                          error:&err];
    if(err) {
        NSLog(@"json解析失败：%@",err);
        return nil;
    }
    return dic;
}

-(void)httppost
{
    NSString *bodyString=@"num1=11111111";
    NSString *RequestUrl=URL1;
    NSData *bodyData = [[bodyString stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]dataUsingEncoding:NSUTF8StringEncoding];//把bodyString转换为NSData数据
    NSURL *serverUrl = [NSURL URLWithString:RequestUrl];//获取到服务器的url地址
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:serverUrl
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:10];
    
    [request setHTTPMethod:@"POST"];//POST请求
    [request setHTTPBody:bodyData];//body 数据
    NSData *returnData = [NSURLConnection sendSynchronousRequest:request returningResponse:nil error:nil];//同步发送request，成功后会得到服务器返回的数据
    NSString *result=[[NSString alloc]initWithData:returnData encoding:NSUTF8StringEncoding];
    NSLog(@"%@",result);
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
//    [self httppost];

    //79a67548-d79d-ea08-a176-10d94ec49f7b
    [JSRSA sharedInstance].publicKey = @"public_key12.pem";
    [JSRSA sharedInstance].privateKey = @"private_key12.pem";
    
    //客户端先生成随机数num1
    num1=@"11111111";
    [self firstPost:URL1 params:[NSDictionary dictionaryWithObjectsAndKeys:num1,@"num1", nil]];
    
    
//    [self DEStest];
    
    
    self.navigationItem.title = @"RSA Demo";
    UIBarButtonItem *resetButton = [[UIBarButtonItem alloc] initWithTitle:@"Reset" style:UIBarButtonItemStylePlain target:self action:@selector(resetTapped:)];
    self.navigationItem.rightBarButtonItem = resetButton;
    self.navigationController.navigationBar.barTintColor = [UIColor colorWithRed:67/255.0 green:74/255.0 blue:84/255.0 alpha:1];
    
    
    
    _scrollView = [[UIScrollView alloc] init];
    _scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_scrollView];
    
    _dummyView = [[UIView alloc] init];
    _dummyView.translatesAutoresizingMaskIntoConstraints = NO;
    _dummyView.backgroundColor = [UIColor clearColor];
    [_scrollView addSubview:_dummyView];
    
    // keyboard tool bar
    UIBarButtonItem *doneBarButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(doneTouched:)];
    [doneBarButton setTitleTextAttributes:[NSDictionary dictionaryWithObjectsAndKeys: [UIColor colorWithRed:87/255.0f green:83/255.0f blue:75/255.0f alpha:1], UITextAttributeTextColor,nil] forState:UIControlStateNormal];
    [doneBarButton setStyle:UIBarButtonItemStyleDone];
    UIToolbar *keyboardToolbar = [[UIToolbar alloc] init];
    [keyboardToolbar setTintColor:[UIColor whiteColor]];
    [keyboardToolbar sizeToFit];
    [keyboardToolbar setItems:[NSArray arrayWithObjects:[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil], doneBarButton, nil]];
    
    // public encrypt
    UILabel *publicEncryptLabel = [[UILabel alloc] init];
    publicEncryptLabel.translatesAutoresizingMaskIntoConstraints = NO;
    publicEncryptLabel.text = @"Public Encrypt";
    [_scrollView addSubview:publicEncryptLabel];
    
    _publicEncryptInputTextView = [[UITextView alloc] init];
    _publicEncryptInputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _publicEncryptInputTextView.text = plainText;
    [_scrollView addSubview:_publicEncryptInputTextView];
    
    _publicEncryptOutputTextView = [[UITextView alloc] init];
    _publicEncryptOutputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _publicEncryptOutputTextView.editable = NO;
    [_scrollView addSubview:_publicEncryptOutputTextView];
    
    _publicEncryptButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _publicEncryptButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_publicEncryptButton setTitle:@"Encrypt" forState:UIControlStateNormal];
    [_publicEncryptButton addTarget:self action:@selector(publicEncryptTouched:) forControlEvents:UIControlEventTouchUpInside];
    [_scrollView addSubview:_publicEncryptButton];
    
    // private decrypt
    UILabel *privateDecryptLabel = [[UILabel alloc] init];
    privateDecryptLabel.translatesAutoresizingMaskIntoConstraints = NO;
    privateDecryptLabel.text = @"Private Decrypt";
    [_scrollView addSubview:privateDecryptLabel];
    
    _privateDecryptInputTextView = [[UITextView alloc] init];
    _privateDecryptInputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _privateDecryptInputTextView.text = publicEncryptedText;
    [_scrollView addSubview:_privateDecryptInputTextView];
    
    _privateDecryptOutputTextView = [[UITextView alloc] init];
    _privateDecryptOutputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _privateDecryptOutputTextView.editable = NO;
    [_scrollView addSubview:_privateDecryptOutputTextView];
    
    _privateDecryptButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _privateDecryptButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_privateDecryptButton setTitle:@"Decrypt" forState:UIControlStateNormal];
    [_privateDecryptButton addTarget:self action:@selector(privateDecryptTouched:) forControlEvents:UIControlEventTouchUpInside];
    [_scrollView addSubview:_privateDecryptButton];
    
    // private encrypt
    UILabel *privateEncryptLabel = [[UILabel alloc] init];
    privateEncryptLabel.translatesAutoresizingMaskIntoConstraints = NO;
    privateEncryptLabel.text = @"Private Encrypt";
    [_scrollView addSubview:privateEncryptLabel];
    
    _privateEncryptInputTextView = [[UITextView alloc] init];
    _privateEncryptInputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _privateEncryptInputTextView.text = plainText;
    [_scrollView addSubview:_privateEncryptInputTextView];
    
    _privateEncryptOutputTextView = [[UITextView alloc] init];
    _privateEncryptOutputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _privateEncryptOutputTextView.editable = NO;
    [_scrollView addSubview:_privateEncryptOutputTextView];
    
    _privateEncryptButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _privateEncryptButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_privateEncryptButton setTitle:@"Encrypt" forState:UIControlStateNormal];
    [_privateEncryptButton addTarget:self action:@selector(privateEncryptTouched:) forControlEvents:UIControlEventTouchUpInside];
    [_scrollView addSubview:_privateEncryptButton];
    
    // public decrypt
    UILabel *publicDecryptLabel = [[UILabel alloc] init];
    publicDecryptLabel.translatesAutoresizingMaskIntoConstraints = NO;
    publicDecryptLabel.text = @"Public Decrypt";
    [_scrollView addSubview:publicDecryptLabel];
    
    _publicDecryptInputTextView = [[UITextView alloc] init];
    _publicDecryptInputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _publicDecryptInputTextView.text = privateEncryptedText;
    [_scrollView addSubview:_publicDecryptInputTextView];
    
    _publicDecryptOutputTextView = [[UITextView alloc] init];
    _publicDecryptOutputTextView.translatesAutoresizingMaskIntoConstraints = NO;
    _publicDecryptOutputTextView.editable = NO;
    [_scrollView addSubview:_publicDecryptOutputTextView];
    
    _publicDecryptButton = [UIButton buttonWithType:UIButtonTypeCustom];
    _publicDecryptButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_publicDecryptButton setTitle:@"Decrypt" forState:UIControlStateNormal];
    [_publicDecryptButton addTarget:self action:@selector(publicDecryptTouched:) forControlEvents:UIControlEventTouchUpInside];
    [_scrollView addSubview:_publicDecryptButton];
    
    // configure textViews
    textViews = @[
                  _publicEncryptInputTextView
                  , _publicEncryptOutputTextView
                  , _privateDecryptInputTextView
                  , _privateDecryptOutputTextView
//                  , _privateEncryptInputTextView
//                  , _privateEncryptOutputTextView
//                  , _publicDecryptInputTextView
//                  , _publicDecryptOutputTextView
                  ];
    for (UITextView *textView in textViews) {
        textView.layer.borderWidth = 1.0f;
        textView.inputAccessoryView = keyboardToolbar;
        textView.font = [UIFont fontWithName:@"HelveticaNeue" size:14];
    }
    
    // configure buttons
    buttons = @[_publicEncryptButton, _privateDecryptButton, _privateEncryptButton, _publicDecryptButton];
    for (UIButton *button in buttons) {
        button.backgroundColor = [UIColor colorWithWhite:0 alpha:0.6];
        [button setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont fontWithName:@"HelveticaNeue" size:18];
    }
    
    labels = @[publicEncryptLabel, privateDecryptLabel, privateEncryptLabel, publicDecryptLabel];
    for (UILabel *label in labels) {
        label.backgroundColor = [UIColor clearColor];
        label.textColor = [UIColor colorWithRed:88/255.0 green:84/255.0 blue:75/255.0 alpha:0.7];
        label.font = [UIFont fontWithName:@"HelveticaNeue-Medium" size:20];
    }
    
    // auto-layout
    NSDictionary *viewsDictionary = NSDictionaryOfVariableBindings(_scrollView
                                                                   , _dummyView
                                                                   , publicEncryptLabel
                                                                   , _publicEncryptInputTextView
                                                                   , _publicEncryptOutputTextView
                                                                   , _publicEncryptButton
                                                                   , publicDecryptLabel
                                                                   , _publicDecryptInputTextView
                                                                   , _publicDecryptOutputTextView
                                                                   , _publicDecryptButton
                                                                   , privateDecryptLabel
                                                                   , _privateDecryptInputTextView
                                                                   , _privateDecryptOutputTextView
                                                                   , _privateDecryptButton
                                                                   , privateEncryptLabel
                                                                   , _privateEncryptInputTextView
                                                                   , _privateEncryptOutputTextView
                                                                   , _privateEncryptButton);
    
    NSDictionary *matrics = @{@"margin": @(10), @"sectionMargin": @(20), @"textHeight": @(50)};
    
    NSArray *constraints = [NSLayoutConstraint
                            constraintsWithVisualFormat:@"V:|[_scrollView]|"
                            options:0
                            metrics:nil
                            views:viewsDictionary];
    [self.view addConstraints:constraints];
    
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|[_scrollView]|"
                   options:0
                   metrics:nil
                   views:viewsDictionary];
    [self.view addConstraints:constraints];
    
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"V:|-sectionMargin-[publicEncryptLabel]-margin-[_publicEncryptInputTextView(textHeight)]-margin-[_publicEncryptOutputTextView(textHeight)]-margin-[_publicEncryptButton]-sectionMargin-[privateDecryptLabel]-margin-[_privateDecryptInputTextView(textHeight)]-margin-[_privateDecryptOutputTextView(textHeight)]-margin-[_privateDecryptButton]-sectionMargin-[privateEncryptLabel]-margin-[_privateEncryptInputTextView(textHeight)]-margin-[_privateEncryptOutputTextView(textHeight)]-margin-[_privateEncryptButton]-sectionMargin-[publicDecryptLabel]-margin-[_publicDecryptInputTextView(textHeight)]-margin-[_publicDecryptOutputTextView(textHeight)]-margin-[_publicDecryptButton]-[_dummyView]-sectionMargin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:[NSString stringWithFormat:@"|-margin-[publicEncryptLabel(%.0f)]-margin-|", [UIScreen mainScreen].bounds.size.width - ([matrics[@"margin"] intValue] * 2)]
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_publicEncryptInputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_publicEncryptOutputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_publicEncryptButton]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[privateDecryptLabel]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_privateDecryptInputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_privateDecryptOutputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_privateDecryptButton]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[publicDecryptLabel]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_publicDecryptInputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_publicDecryptOutputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_publicDecryptButton]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[privateEncryptLabel]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_privateEncryptInputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_privateEncryptOutputTextView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_privateEncryptButton]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    constraints = [NSLayoutConstraint
                   constraintsWithVisualFormat:@"|-margin-[_dummyView]-margin-|"
                   options:0
                   metrics:matrics
                   views:viewsDictionary];
    [_scrollView addConstraints:constraints];
    
    _dummyViewHeightConstraint = [NSLayoutConstraint
                                  constraintWithItem:_dummyView
                                  attribute:NSLayoutAttributeHeight
                                  relatedBy:NSLayoutRelationEqual
                                  toItem:nil
                                  attribute:NSLayoutAttributeNotAnAttribute
                                  multiplier:1.0f
                                  constant:0];
    [_dummyView addConstraint:_dummyViewHeightConstraint];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardWillShow:) name:UIKeyboardWillShowNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardWillHide:) name:UIKeyboardWillHideNotification object:nil];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - 公钥加密
- (void)publicEncryptTouched:(UIButton *)sender
{
    _publicEncryptOutputTextView.text = [[JSRSA sharedInstance] publicEncrypt:_publicEncryptInputTextView.text];
    _privateDecryptInputTextView.text=_publicEncryptOutputTextView.text;
}

#pragma mark - 私钥解密
- (void)privateDecryptTouched:(UIButton *)sender
{
    _privateDecryptOutputTextView.text = [[JSRSA sharedInstance] privateDecrypt:_privateDecryptInputTextView.text];
}

- (void)privateEncryptTouched:(UIButton *)sender
{
    _privateEncryptOutputTextView.text = [[JSRSA sharedInstance] privateEncrypt:_privateEncryptInputTextView.text];
}

- (void)publicDecryptTouched:(UIButton *)sender
{
    _publicDecryptOutputTextView.text = [[JSRSA sharedInstance] publicDecrypt:_publicDecryptInputTextView.text];
}

- (void)doneTouched:(UIBarButtonItem *)sender
{
    [self.view endEditing:YES];
}

- (void)resetTapped:(UIBarButtonItem *)sender
{
    _publicEncryptInputTextView.text = plainText;
    _publicEncryptOutputTextView.text = @"";
    _privateDecryptInputTextView.text = publicEncryptedText;
    _privateDecryptOutputTextView.text = @"";
    _privateEncryptInputTextView.text = plainText;
    _privateEncryptOutputTextView.text = @"";
    _publicDecryptInputTextView.text = privateEncryptedText;
    _publicDecryptOutputTextView.text = @"";
}

#pragma mark - keyboard notification
- (void)keyboardWillShow:(NSNotification *)notification
{
    NSDictionary *userInfo = [notification userInfo];
    CGSize keyboardSize = [[userInfo objectForKey:UIKeyboardFrameBeginUserInfoKey] CGRectValue].size;
    
    [_dummyView removeConstraint:_dummyViewHeightConstraint];
    
    _dummyViewHeightConstraint = [NSLayoutConstraint constraintWithItem:_dummyView
                                                              attribute:NSLayoutAttributeHeight
                                                              relatedBy:NSLayoutRelationEqual
                                                                 toItem:nil
                                                              attribute:NSLayoutAttributeNotAnAttribute
                                                             multiplier:1.0f
                                                               constant:keyboardSize.height];
    [_dummyView addConstraint:_dummyViewHeightConstraint];
}

- (void)keyboardWillHide:(NSNotification *)notification
{
    [_dummyView removeConstraint:_dummyViewHeightConstraint];
    
    _dummyViewHeightConstraint = [NSLayoutConstraint constraintWithItem:_dummyView
                                                              attribute:NSLayoutAttributeHeight
                                                              relatedBy:NSLayoutRelationEqual
                                                                 toItem:nil
                                                              attribute:NSLayoutAttributeNotAnAttribute
                                                             multiplier:1.0f
                                                               constant:0];
    [_dummyView addConstraint:_dummyViewHeightConstraint];
}

@end
